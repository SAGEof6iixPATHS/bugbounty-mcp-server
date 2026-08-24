"""Auditable, bounded tools exposed by the MCP server."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import re
import shutil
import socket
import ssl
from collections import Counter, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import aiohttp
import dns.exception
import dns.resolver
import yaml
from aiohttp.abc import AbstractResolver, ResolveResult
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from jsonschema import Draft202012Validator, FormatChecker
from mcp.types import Tool, ToolAnnotations

from .. import __version__
from ..config import BugBountyConfig
from ..findings import CONFIDENCES, SEVERITIES, STATUSES, FindingStore
from ..scope import ScopePolicy, ScopeViolation, parse_target
from ..utils import RateLimiter, bounded_map, parse_ports, run_command_async, stable_hash, utc_now

logger = logging.getLogger(__name__)

_COMMON_SUBDOMAINS = [
    "www",
    "api",
    "admin",
    "app",
    "auth",
    "blog",
    "cdn",
    "dev",
    "docs",
    "help",
    "mail",
    "m",
    "portal",
    "shop",
    "staging",
    "status",
    "support",
    "test",
    "vpn",
]
_COMMON_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "favicon.ico",
    "login",
    "admin",
    "api",
    "api/v1",
    "docs",
    "swagger.json",
    "openapi.json",
]
_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.yaml",
    "/api-docs",
    "/v3/api-docs",
]
_SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SENSITIVE_RESPONSE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}


class ToolExecutionError(RuntimeError):
    """Expected, user-correctable tool error."""

    def __init__(self, message: str, *, code: str = "tool_error"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ToolSpec:
    definition: Tool
    handler: Callable[..., Awaitable[dict[str, Any]]]
    validator: Draft202012Validator
    output_validator: Draft202012Validator


@dataclass(slots=True)
class HTTPResponse:
    requested_url: str
    final_url: str
    status: int
    reason: str
    headers: dict[str, str]
    set_cookies: list[str]
    body: bytes
    content_type: str
    redirects: list[dict[str, Any]]
    truncated: bool
    elapsed_ms: float


class _ScopeResolver(AbstractResolver):
    """Resolve once, validate every answer, then hand pinned IPs to aiohttp."""

    def __init__(self, policy: ScopePolicy):
        self.policy = policy

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_UNSPEC,
    ) -> list[ResolveResult]:
        _parsed, addresses = await self.policy.resolve_network_safe(host)
        results: list[ResolveResult] = []
        for address in addresses:
            address_family = socket.AF_INET6 if ":" in address else socket.AF_INET
            if family not in {socket.AF_UNSPEC, address_family}:
                continue
            results.append(
                ResolveResult(
                    hostname=host,
                    host=address,
                    port=port,
                    family=address_family,
                    proto=socket.IPPROTO_TCP,
                    flags=socket.AI_NUMERICHOST,
                )
            )
        if not results:
            raise OSError(f"no validated address for {host} matches address family {family}")
        return results

    async def close(self) -> None:
        return None


class _HTMLInspector(HTMLParser):
    def __init__(self, *, max_links: int, max_forms: int) -> None:
        super().__init__(convert_charrefs=True)
        self.max_links = max_links
        self.max_forms = max_forms
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self.generators: list[str] = []
        self.links_truncated = False
        self.forms_truncated = False
        self._title_parts: list[str] = []
        self._in_title = False

    @property
    def title(self) -> str | None:
        title = " ".join("".join(self._title_parts).split())
        return title[:300] or None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and attributes.get("href"):
            if len(self.links) < self.max_links:
                self.links.append(attributes["href"] or "")
            else:
                self.links_truncated = True
        elif tag == "form":
            if len(self.forms) < self.max_forms:
                self.forms.append(
                    {
                        "action": attributes.get("action") or "",
                        "method": (attributes.get("method") or "GET").upper(),
                    }
                )
            else:
                self.forms_truncated = True
        elif tag == "script" and attributes.get("src") and len(self.scripts) < self.max_links:
            self.scripts.append(attributes["src"] or "")
        elif tag == "meta" and (attributes.get("name") or "").lower() == "generator":
            if attributes.get("content") and len(self.generators) < self.max_forms:
                self.generators.append(attributes["content"] or "")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


class _NoAliasSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects aliases to prevent expansion bombs."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not accepted")
        return super().compose_node(parent, index)


def _bounded_structure_size(value: Any, *, maximum: int = 100_000) -> int:
    """Count decoded container nodes without recursion and reject oversized documents."""
    pending = [value]
    count = 0
    while pending:
        item = pending.pop()
        count += 1
        if count > maximum:
            raise ValueError(f"document exceeds the {maximum}-node structure limit")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return count


def _object_schema(
    properties: dict[str, Any],
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


_OUTPUT_SHAPES: dict[str, dict[str, str]] = {
    "scope_check": {"allowed": "boolean", "reason": "string"},
    "batch_scope_check": {
        "decisions": "array",
        "total": "integer",
        "allowed": "integer",
        "denied": "integer",
    },
    "dns_enumeration": {"target": "string", "queried_at": "string", "records": "object"},
    "email_security_analysis": {
        "domain": "string",
        "records": "object",
        "findings": "array",
        "finding_count": "integer",
    },
    "subdomain_enumeration": {
        "domain": "string",
        "subdomains": "array",
        "count": "integer",
    },
    "http_probe": {"requested_url": "string", "final_url": "string", "status": "integer"},
    "headers_analysis": {"url": "string", "status": "integer", "score": "integer"},
    "cors_scan": {"url": "string", "tests": "array", "findings": "array"},
    "cookie_security_analysis": {
        "url": "string",
        "cookies": "array",
        "cookie_count": "integer",
    },
    "security_txt_analysis": {"origin": "string", "present": "boolean", "findings": "array"},
    "openapi_discovery": {
        "documents": "array",
        "document_count": "integer",
        "attempts": "array",
    },
    "ssl_scan": {"target": "string", "port": "integer", "trusted_for_host": "boolean"},
    "port_scan": {
        "target": "string",
        "ports_scanned": "integer",
        "open_ports": "array",
    },
    "web_crawler": {"pages": "array", "page_count": "integer", "limits": "object"},
    "web_directory_scan": {"requests": "integer", "results": "array"},
    "jwt_security_test": {"header": "object", "payload": "object", "findings": "array"},
    "nuclei_scan": {"target": "string", "findings": "array", "finding_count": "integer"},
    "create_finding": {"finding": "object"},
    "add_finding_evidence": {"evidence": "object"},
    "list_findings": {"findings": "array", "count": "integer"},
    "update_finding": {"finding": "object"},
    "generate_vulnerability_report": {
        "path": "string",
        "total_findings": "integer",
        "findings": "array",
    },
    "assessment_summary": {"scope": "object", "findings": "object", "runtime": "object"},
    "server_health": {"status": "string", "version": "string", "tools": "integer"},
}


def _output_schema(name: str) -> dict[str, Any]:
    fields = _OUTPUT_SHAPES[name]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {key: {"type": value} for key, value in fields.items()},
        "required": list(fields),
        "additionalProperties": True,
    }


def _annotation(
    *, read_only: bool, destructive: bool = False, open_world: bool = True
) -> ToolAnnotations:
    return ToolAnnotations(
        read_only_hint=read_only,
        destructive_hint=destructive,
        idempotent_hint=read_only,
        open_world_hint=open_world,
    )


class SecurityTools:
    """Registry and implementation of the supported production tool surface."""

    def __init__(self, config: BugBountyConfig):
        self.config = config
        self.scope = ScopePolicy(config)
        self._public_resolver = _ScopeResolver(
            ScopePolicy(BugBountyConfig(safe_mode=False, allow_private_targets=False))
        )
        self.rate_limiter = RateLimiter(config.requests_per_second)
        self.findings = FindingStore(
            config.output.data_dir,
            config.output.output_dir,
            max_evidence_bytes=config.output.max_evidence_bytes,
        )
        self._started_at = utc_now()
        self._metrics: Counter[str] = Counter()
        self._active_calls = 0
        self._per_tool_calls: Counter[str] = Counter()
        self._specs = self._build_specs()

    @property
    def specs(self) -> dict[str, ToolSpec]:
        return dict(self._specs)

    def get_tools(self) -> list[Tool]:
        return [spec.definition for spec in self._specs.values()]

    async def call(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        spec = self._specs.get(name)
        if spec is None:
            raise ToolExecutionError(f"unknown tool: {name}", code="unknown_tool")
        payload = arguments or {}
        errors = sorted(spec.validator.iter_errors(payload), key=lambda error: list(error.path))
        if errors:
            details = []
            for error in errors[:10]:
                location = ".".join(str(part) for part in error.absolute_path) or "$"
                details.append(f"{location}: {error.message}")
            raise ToolExecutionError(
                "invalid arguments: " + "; ".join(details), code="invalid_args"
            )
        self._metrics["calls"] += 1
        self._per_tool_calls[name] += 1
        self._active_calls += 1
        started = asyncio.get_running_loop().time()
        try:
            result = await spec.handler(**payload)
            output_errors = list(spec.output_validator.iter_errors(result))
            if output_errors:
                raise RuntimeError(f"tool {name} produced invalid structured output")
            self._metrics["succeeded"] += 1
            return result
        except ToolExecutionError:
            self._metrics["rejected"] += 1
            raise
        except ScopeViolation as exc:
            self._metrics["rejected"] += 1
            raise ToolExecutionError(str(exc), code="target_not_allowed") from exc
        except ValueError as exc:
            self._metrics["rejected"] += 1
            raise ToolExecutionError(str(exc), code="invalid_args") from exc
        except asyncio.CancelledError:
            self._metrics["cancelled"] += 1
            raise
        except Exception:
            self._metrics["failed"] += 1
            raise
        finally:
            self._active_calls -= 1
            elapsed_ms = (asyncio.get_running_loop().time() - started) * 1000
            self._metrics["duration_ms_total"] += round(elapsed_ms)

    def _spec(
        self,
        name: str,
        title: str,
        description: str,
        schema: dict[str, Any],
        handler: Callable[..., Awaitable[dict[str, Any]]],
        *,
        read_only: bool = True,
        destructive: bool = False,
        open_world: bool = True,
    ) -> ToolSpec:
        output_schema = _output_schema(name)
        definition = Tool(
            name=name,
            title=title,
            description=description,
            input_schema=schema,
            output_schema=output_schema,
            annotations=_annotation(
                read_only=read_only,
                destructive=destructive,
                open_world=open_world,
            ),
        )
        return ToolSpec(
            definition=definition,
            handler=handler,
            validator=Draft202012Validator(schema, format_checker=FormatChecker()),
            output_validator=Draft202012Validator(output_schema),
        )

    def _build_specs(self) -> dict[str, ToolSpec]:
        string_target = {"type": "string", "minLength": 1, "maxLength": 2048}
        specs = [
            self._spec(
                "scope_check",
                "Check target scope",
                "Validate and explain whether a target is authorized; performs no network request.",
                _object_schema({"target": string_target}, required=["target"]),
                self.scope_check,
                open_world=False,
            ),
            self._spec(
                "batch_scope_check",
                "Check multiple targets",
                "Canonicalize and evaluate up to 100 targets without network activity.",
                _object_schema(
                    {
                        "targets": {
                            "type": "array",
                            "items": string_target,
                            "minItems": 1,
                            "maxItems": 100,
                            "uniqueItems": True,
                        }
                    },
                    required=["targets"],
                ),
                self.batch_scope_check,
                open_world=False,
            ),
            self._spec(
                "dns_enumeration",
                "Enumerate DNS records",
                "Resolve selected DNS record types for one authorized domain.",
                _object_schema(
                    {
                        "domain": string_target,
                        "record_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"],
                            },
                            "uniqueItems": True,
                            "minItems": 1,
                            "maxItems": 8,
                        },
                    },
                    required=["domain"],
                ),
                self.dns_enumeration,
            ),
            self._spec(
                "email_security_analysis",
                "Audit email-domain security",
                "Inspect MX, SPF, DMARC, MTA-STS, and SMTP TLS reporting records for an "
                "authorized domain.",
                _object_schema({"domain": string_target}, required=["domain"]),
                self.email_security_analysis,
            ),
            self._spec(
                "subdomain_enumeration",
                "Enumerate subdomains",
                "Query certificate-transparency logs and optionally resolve "
                "a bounded candidate list.",
                _object_schema(
                    {
                        "domain": string_target,
                        "active": {"type": "boolean", "default": False},
                        "candidates": {
                            "type": "array",
                            "items": {"type": "string", "pattern": "^[A-Za-z0-9-]{1,63}$"},
                            "uniqueItems": True,
                            "minItems": 1,
                            "maxItems": 100,
                        },
                    },
                    required=["domain"],
                ),
                self.subdomain_enumeration,
            ),
            self._spec(
                "http_probe",
                "Probe an HTTP endpoint",
                "Fetch one authorized URL with bounded redirects/body size and return "
                "metadata, not body data.",
                _object_schema(
                    {
                        "url": string_target,
                        "method": {"type": "string", "enum": ["GET", "HEAD"], "default": "GET"},
                        "follow_redirects": {"type": "boolean", "default": True},
                    },
                    required=["url"],
                ),
                self.http_probe,
            ),
            self._spec(
                "headers_analysis",
                "Audit HTTP security headers",
                "Analyze security and disclosure headers on one authorized HTTP endpoint.",
                _object_schema({"url": string_target}, required=["url"]),
                self.headers_analysis,
            ),
            self._spec(
                "cors_scan",
                "Audit CORS behavior",
                "Send bounded cross-origin probes and identify permissive CORS responses.",
                _object_schema(
                    {
                        "url": string_target,
                        "origins": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1, "maxLength": 500},
                            "minItems": 1,
                            "maxItems": 5,
                            "uniqueItems": True,
                        },
                    },
                    required=["url"],
                ),
                self.cors_scan,
            ),
            self._spec(
                "cookie_security_analysis",
                "Audit response cookies",
                "Inspect Set-Cookie attributes without sending authentication material.",
                _object_schema({"url": string_target}, required=["url"]),
                self.cookie_security_analysis,
            ),
            self._spec(
                "security_txt_analysis",
                "Audit security.txt",
                "Discover and validate RFC 9116 security.txt metadata on an authorized origin.",
                _object_schema({"url": string_target}, required=["url"]),
                self.security_txt_analysis,
            ),
            self._spec(
                "openapi_discovery",
                "Discover OpenAPI descriptions",
                "Probe a bounded list of conventional paths and summarize OpenAPI/Swagger "
                "documents without returning their full contents.",
                _object_schema(
                    {
                        "url": string_target,
                        "paths": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1, "maxLength": 500},
                            "uniqueItems": True,
                            "minItems": 1,
                            "maxItems": 10,
                        },
                    },
                    required=["url"],
                ),
                self.openapi_discovery,
            ),
            self._spec(
                "ssl_scan",
                "Inspect a TLS certificate",
                "Inspect certificate identity, validity, protocol, cipher, and trust "
                "for an authorized host.",
                _object_schema(
                    {
                        "target": string_target,
                        "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 443},
                    },
                    required=["target"],
                ),
                self.ssl_scan,
            ),
            self._spec(
                "port_scan",
                "Scan TCP ports",
                "Perform a bounded TCP connect scan against one authorized host.",
                _object_schema(
                    {
                        "target": string_target,
                        "ports": {
                            "type": "string",
                            "maxLength": 4096,
                            "description": "Comma-separated ports/ranges, e.g. 80,443,8000-8010",
                        },
                    },
                    required=["target"],
                ),
                self.port_scan,
            ),
            self._spec(
                "web_crawler",
                "Crawl a website",
                "Crawl a bounded number of same-host HTML pages and inventory links and forms.",
                _object_schema(
                    {
                        "url": string_target,
                        "max_pages": {"type": "integer", "minimum": 1, "maximum": 200},
                        "max_depth": {"type": "integer", "minimum": 0, "maximum": 5},
                    },
                    required=["url"],
                ),
                self.web_crawler,
            ),
            self._spec(
                "web_directory_scan",
                "Discover common web paths",
                "Probe a bounded path list on one authorized web origin.",
                _object_schema(
                    {
                        "url": string_target,
                        "paths": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1, "maxLength": 500},
                            "uniqueItems": True,
                            "minItems": 1,
                            "maxItems": 1000,
                        },
                    },
                    required=["url"],
                ),
                self.web_directory_scan,
            ),
            self._spec(
                "jwt_security_test",
                "Analyze a JWT",
                "Decode JWT metadata locally and flag unsafe algorithms or claim timing; "
                "does not verify a signature.",
                _object_schema(
                    {"jwt_token": {"type": "string", "minLength": 3, "maxLength": 65536}},
                    required=["jwt_token"],
                ),
                self.jwt_security_test,
                open_world=False,
            ),
            self._spec(
                "nuclei_scan",
                "Run Nuclei",
                "Run the locally installed Nuclei scanner against one authorized target "
                "when explicitly enabled.",
                _object_schema(
                    {
                        "target": string_target,
                        "severity": {
                            "type": "array",
                            "items": {"type": "string", "enum": _SEVERITY_ORDER},
                            "uniqueItems": True,
                            "minItems": 1,
                            "maxItems": 5,
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,50}$"},
                            "uniqueItems": True,
                            "minItems": 1,
                            "maxItems": 20,
                        },
                    },
                    required=["target"],
                ),
                self.nuclei_scan,
            ),
            self._spec(
                "create_finding",
                "Create a finding",
                "Persist a structured security finding in the local finding store.",
                _object_schema(
                    {
                        "title": {"type": "string", "minLength": 1, "maxLength": 300},
                        "severity": {"type": "string", "enum": sorted(SEVERITIES)},
                        "target": string_target,
                        "description": {"type": "string", "minLength": 1, "maxLength": 50000},
                        "evidence": {"type": "string", "maxLength": 100000},
                        "remediation": {"type": "string", "maxLength": 50000},
                        "references": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 2048},
                            "maxItems": 50,
                        },
                        "impact": {"type": "string", "maxLength": 50000},
                        "steps_to_reproduce": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1, "maxLength": 10000},
                            "maxItems": 50,
                        },
                        "cwe": {
                            "type": "string",
                            "pattern": "^(CWE-[0-9]+|NVD-CWE-(OTHER|NOINFO))$",
                        },
                        "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                        "confidence": {"type": "string", "enum": sorted(CONFIDENCES)},
                        "tags": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "pattern": "^[A-Za-z0-9_.:-]{1,50}$",
                            },
                            "uniqueItems": True,
                            "maxItems": 30,
                        },
                        "source_tool": {"type": "string", "maxLength": 100},
                    },
                    required=["title", "severity", "target", "description"],
                ),
                self.create_finding,
                read_only=False,
                open_world=False,
            ),
            self._spec(
                "add_finding_evidence",
                "Attach finding evidence",
                "Store a private, hashed text evidence artifact and link it to a finding.",
                _object_schema(
                    {
                        "finding_id": {"type": "string", "format": "uuid"},
                        "label": {"type": "string", "minLength": 1, "maxLength": 200},
                        "content": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": self.config.output.max_evidence_bytes,
                        },
                        "media_type": {
                            "type": "string",
                            "enum": [
                                "text/plain",
                                "text/markdown",
                                "text/html",
                                "text/csv",
                                "application/json",
                                "application/xml",
                            ],
                        },
                    },
                    required=["finding_id", "label", "content"],
                ),
                self.add_finding_evidence,
                read_only=False,
                open_world=False,
            ),
            self._spec(
                "list_findings",
                "List findings",
                "List locally persisted findings with optional filters.",
                _object_schema(
                    {
                        "target": string_target,
                        "severity": {"type": "string", "enum": sorted(SEVERITIES)},
                        "status": {"type": "string", "enum": sorted(STATUSES)},
                    }
                ),
                self.list_findings,
                open_world=False,
            ),
            self._spec(
                "update_finding",
                "Update a finding",
                "Update status, remediation, and audit history for a local finding.",
                _object_schema(
                    {
                        "finding_id": {"type": "string", "format": "uuid"},
                        "status": {"type": "string", "enum": sorted(STATUSES)},
                        "remediation": {"type": "string", "maxLength": 50000},
                        "note": {"type": "string", "maxLength": 5000},
                    },
                    required=["finding_id", "status"],
                ),
                self.update_finding,
                read_only=False,
                open_world=False,
            ),
            self._spec(
                "generate_vulnerability_report",
                "Generate a vulnerability report",
                "Export current findings as JSON, Markdown, escaped HTML, or SARIF 2.1.0.",
                _object_schema(
                    {
                        "report_format": {
                            "type": "string",
                            "enum": ["json", "markdown", "html", "sarif"],
                            "default": "json",
                        },
                        "target": string_target,
                    }
                ),
                self.generate_vulnerability_report,
                read_only=False,
                open_world=False,
            ),
            self._spec(
                "assessment_summary",
                "Summarize assessment state",
                "Summarize finding severity/status, targets, scope readiness, and runtime metrics.",
                _object_schema({}),
                self.assessment_summary,
                open_world=False,
            ),
            self._spec(
                "server_health",
                "Inspect server health",
                "Report safe configuration and optional dependency status without "
                "exposing secrets.",
                _object_schema({}),
                self.server_health,
                open_world=False,
            ),
        ]
        return {spec.definition.name: spec for spec in specs}

    async def scope_check(self, target: str) -> dict[str, Any]:
        return self.scope.evaluate(target).to_dict()

    async def batch_scope_check(self, targets: list[str]) -> dict[str, Any]:
        decisions = [self.scope.evaluate(target).to_dict() for target in targets]
        allowed = sum(bool(decision["allowed"]) for decision in decisions)
        return {
            "decisions": decisions,
            "total": len(decisions),
            "allowed": allowed,
            "denied": len(decisions) - allowed,
        }

    async def dns_enumeration(
        self,
        domain: str,
        record_types: list[str] | None = None,
    ) -> dict[str, Any]:
        parsed = await self.scope.require_network_safe(domain)
        if parsed.kind != "domain":
            raise ValueError("dns_enumeration requires a domain name")
        selected = record_types or ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

        async def resolve(record_type: str) -> tuple[str, list[str], str | None]:
            await self.rate_limiter.wait()

            def query() -> list[str]:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = min(10.0, self.config.scanning.request_timeout)
                return [
                    str(answer).rstrip(".") for answer in resolver.resolve(parsed.host, record_type)
                ]

            try:
                return record_type, await asyncio.to_thread(query), None
            except (dns.exception.DNSException, OSError) as exc:
                return record_type, [], exc.__class__.__name__

        resolved = await asyncio.gather(*(resolve(record_type) for record_type in selected))
        return {
            "target": parsed.host,
            "queried_at": utc_now(),
            "records": {
                record_type: {"values": values, "error": error}
                for record_type, values, error in resolved
            },
        }

    async def email_security_analysis(self, domain: str) -> dict[str, Any]:
        parsed = await self.scope.require_network_safe(domain)
        if parsed.kind != "domain":
            raise ValueError("email_security_analysis requires a domain name")

        queries = {
            "mx": (parsed.host, "MX"),
            "spf": (parsed.host, "TXT"),
            "dmarc": (f"_dmarc.{parsed.host}", "TXT"),
            "mta_sts": (f"_mta-sts.{parsed.host}", "TXT"),
            "tls_reporting": (f"_smtp._tls.{parsed.host}", "TXT"),
        }

        async def query(name: str, record_type: str) -> tuple[list[str], str | None]:
            await self.rate_limiter.wait()

            def resolve() -> list[str]:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = min(10.0, self.config.scanning.request_timeout)
                values = []
                for answer in resolver.resolve(name, record_type):
                    raw = str(answer).rstrip(".")
                    if record_type == "TXT":
                        fragments = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', raw)
                        values.append("".join(fragments) if fragments else raw.strip('"'))
                    else:
                        values.append(raw)
                return values

            try:
                return await asyncio.to_thread(resolve), None
            except (dns.exception.DNSException, OSError) as exc:
                return [], exc.__class__.__name__

        results = await asyncio.gather(*(query(name, kind) for name, kind in queries.values()))
        records: dict[str, dict[str, Any]] = {
            label: {"values": values, "error": error}
            for label, (values, error) in zip(queries, results, strict=True)
        }
        txt_records = records["spf"]["values"]
        spf_records = [value for value in txt_records if value.lower().startswith("v=spf1")]
        dmarc_records = [
            value for value in records["dmarc"]["values"] if value.lower().startswith("v=dmarc1")
        ]
        findings: list[dict[str, str]] = []
        if not records["mx"]["values"]:
            findings.append({"severity": "medium", "issue": "no MX record was found"})
        if not spf_records:
            findings.append({"severity": "medium", "issue": "no SPF policy was found"})
        elif len(spf_records) > 1:
            findings.append({"severity": "high", "issue": "multiple SPF policies invalidate SPF"})
        elif "+all" in spf_records[0].lower():
            findings.append({"severity": "high", "issue": "SPF explicitly permits every sender"})
        elif "~all" in spf_records[0].lower() or "?all" in spf_records[0].lower():
            findings.append(
                {"severity": "low", "issue": "SPF uses a soft or neutral all mechanism"}
            )
        if not dmarc_records:
            findings.append({"severity": "medium", "issue": "no DMARC policy was found"})
        elif re.search(r"(?:^|;)\s*p\s*=\s*none(?:;|$)", dmarc_records[0], re.I):
            findings.append(
                {"severity": "low", "issue": "DMARC policy is monitoring-only (p=none)"}
            )
        if not records["mta_sts"]["values"]:
            findings.append({"severity": "info", "issue": "no MTA-STS record was found"})
        if not records["tls_reporting"]["values"]:
            findings.append({"severity": "info", "issue": "no SMTP TLS reporting record was found"})
        return {
            "domain": parsed.host,
            "analyzed_at": utc_now(),
            "records": records,
            "findings": findings,
            "finding_count": len(findings),
        }

    async def subdomain_enumeration(
        self,
        domain: str,
        active: bool = False,
        candidates: list[str] | None = None,
    ) -> dict[str, Any]:
        parsed = await self.scope.require_network_safe(domain)
        if parsed.kind != "domain":
            raise ValueError("subdomain_enumeration requires a domain name")
        found: set[str] = set()
        errors: list[str] = []

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.scanning.request_timeout)
            connector = aiohttp.TCPConnector(
                resolver=self._public_resolver,
                use_dns_cache=False,
            )
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": self.config.user_agent},
                connector=connector,
            ) as session:
                await self.rate_limiter.wait()
                async with session.get(
                    "https://crt.sh/",
                    params={"q": f"%.{parsed.host}", "output": "json"},
                    allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        errors.append(
                            f"certificate transparency query returned HTTP {response.status}"
                        )
                    else:
                        payload = await response.content.read(
                            self.config.scanning.max_response_bytes + 1
                        )
                        if len(payload) > self.config.scanning.max_response_bytes:
                            errors.append(
                                "certificate transparency response exceeded the size limit"
                            )
                        else:
                            certificates = json.loads(payload)
                            if not isinstance(certificates, list):
                                raise json.JSONDecodeError(
                                    "certificate transparency result is not an array",
                                    payload.decode("utf-8", errors="replace"),
                                    0,
                                )
                            for certificate in certificates:
                                if not isinstance(certificate, dict):
                                    continue
                                for name in str(certificate.get("name_value", "")).splitlines():
                                    normalized = name.strip().lower().lstrip("*.").rstrip(".")
                                    if normalized == parsed.host or normalized.endswith(
                                        f".{parsed.host}"
                                    ):
                                        try:
                                            candidate = parse_target(normalized)
                                        except ValueError:
                                            continue
                                        if candidate.kind == "domain":
                                            found.add(candidate.host)
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"certificate transparency query failed: {exc.__class__.__name__}")

        resolved: dict[str, list[str]] = {}
        if active:
            prefixes = candidates or _COMMON_SUBDOMAINS

            async def resolve_candidate(prefix: str) -> tuple[str, list[str]]:
                hostname = f"{prefix.lower()}.{parsed.host}"
                try:
                    _candidate, addresses = await self.scope.resolve_network_safe(hostname)
                    return hostname, list(addresses)
                except (OSError, ScopeViolation):
                    return hostname, []

            entries = await bounded_map(
                prefixes,
                resolve_candidate,
                concurrency=min(self.config.scanning.max_concurrency, 30),
            )
            for hostname, addresses in entries:
                if addresses:
                    found.add(hostname)
                    resolved[hostname] = addresses

        return {
            "domain": parsed.host,
            "enumerated_at": utc_now(),
            "active": active,
            "subdomains": sorted(found),
            "resolved": resolved,
            "count": len(found),
            "errors": errors,
        }

    async def _fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> HTTPResponse:
        parsed = self.scope.require(url, require_url=True)
        current = parsed.normalized or url
        redirects: list[dict[str, Any]] = []
        timeout = aiohttp.ClientTimeout(total=self.config.scanning.request_timeout)
        request_headers = {"User-Agent": self.config.user_agent, **(headers or {})}
        started = asyncio.get_running_loop().time()

        connector = aiohttp.TCPConnector(
            resolver=_ScopeResolver(self.scope),
            use_dns_cache=False,
        )
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers=request_headers,
            connector=connector,
        ) as session:
            for redirect_index in range(self.config.scanning.max_redirects + 1):
                self.scope.require(current, require_url=True)
                await self.rate_limiter.wait()
                try:
                    async with session.request(
                        method,
                        current,
                        allow_redirects=False,
                    ) as response:
                        location = response.headers.get("Location")
                        if follow_redirects and response.status in _REDIRECT_STATUSES and location:
                            if redirect_index >= self.config.scanning.max_redirects:
                                raise ToolExecutionError(
                                    "redirect limit exceeded", code="redirect_limit"
                                )
                            next_url = urljoin(current, location)
                            next_target = self.scope.require(next_url, require_url=True)
                            redirects.append(
                                {
                                    "from": current,
                                    "status": response.status,
                                    "to": next_target.normalized,
                                }
                            )
                            current = next_target.normalized or next_url
                            if response.status == 303:
                                method = "GET"
                            continue

                        body = b""
                        truncated = False
                        if method != "HEAD":
                            body = await response.content.read(
                                self.config.scanning.max_response_bytes + 1
                            )
                            if len(body) > self.config.scanning.max_response_bytes:
                                body = body[: self.config.scanning.max_response_bytes]
                                truncated = True
                        elapsed = (asyncio.get_running_loop().time() - started) * 1000
                        return HTTPResponse(
                            requested_url=url,
                            final_url=str(response.url),
                            status=response.status,
                            reason=response.reason or "",
                            headers={key.lower(): value for key, value in response.headers.items()},
                            set_cookies=response.headers.getall("Set-Cookie", []),
                            body=body,
                            content_type=response.headers.get("Content-Type", ""),
                            redirects=redirects,
                            truncated=truncated,
                            elapsed_ms=round(elapsed, 2),
                        )
                except aiohttp.ClientError as exc:
                    raise ToolExecutionError(
                        f"HTTP request failed: {exc.__class__.__name__}: {exc}",
                        code="http_error",
                    ) from exc
        raise ToolExecutionError("HTTP request did not produce a response", code="http_error")

    def _inspect_html(self, response: HTTPResponse) -> _HTMLInspector:
        inspector = _HTMLInspector(
            max_links=self.config.scanning.max_links_per_page,
            max_forms=self.config.scanning.max_forms_per_page,
        )
        if "html" not in response.content_type.lower() or not response.body:
            return inspector
        charset = "utf-8"
        match = re.search(r"charset=([^;\s]+)", response.content_type, re.I)
        if match:
            charset = match.group(1).strip("\"'")
        try:
            content = response.body.decode(charset, errors="replace")
        except LookupError:
            content = response.body.decode("utf-8", errors="replace")
        inspector.feed(content)
        return inspector

    @staticmethod
    def _detect_technologies(response: HTTPResponse, inspector: _HTMLInspector) -> list[str]:
        detected: set[str] = set()
        headers = response.headers
        if headers.get("server"):
            detected.add(f"Server: {headers['server'][:100]}")
        if headers.get("x-powered-by"):
            detected.add(f"X-Powered-By: {headers['x-powered-by'][:100]}")
        for generator in inspector.generators:
            detected.add(f"Generator: {generator[:100]}")
        scripts = " ".join(inspector.scripts).lower()
        fingerprints = {
            "react": "React",
            "vue": "Vue.js",
            "angular": "Angular",
            "jquery": "jQuery",
            "wp-content": "WordPress",
        }
        for marker, technology in fingerprints.items():
            if marker in scripts:
                detected.add(technology)
        return sorted(detected)

    async def http_probe(
        self,
        url: str,
        method: str = "GET",
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
        response = await self._fetch(url, method=method, follow_redirects=follow_redirects)
        inspector = self._inspect_html(response)
        safe_headers = {
            name: value
            for name, value in response.headers.items()
            if name not in _SENSITIVE_RESPONSE_HEADERS
        }
        return {
            "requested_url": url,
            "final_url": response.final_url,
            "status": response.status,
            "reason": response.reason,
            "content_type": response.content_type,
            "content_length_read": len(response.body),
            "content_sha256": stable_hash(response.body),
            "body_truncated": response.truncated,
            "elapsed_ms": response.elapsed_ms,
            "redirects": response.redirects,
            "title": inspector.title,
            "technologies": self._detect_technologies(response, inspector),
            "headers": safe_headers,
            "redacted_header_names": sorted(
                name for name in response.headers if name in _SENSITIVE_RESPONSE_HEADERS
            ),
            "set_cookie_count": len(response.set_cookies),
        }

    async def headers_analysis(self, url: str) -> dict[str, Any]:
        response = await self._fetch(url)
        headers = response.headers
        is_https = urlsplit(response.final_url).scheme == "https"
        controls: dict[str, dict[str, Any]] = {
            "content-security-policy": {
                "weight": 25,
                "recommendation": "Define a restrictive Content-Security-Policy.",
            },
            "strict-transport-security": {
                "weight": 20 if is_https else 0,
                "recommendation": "On HTTPS, enable HSTS after validating all subdomains.",
            },
            "x-content-type-options": {
                "weight": 15,
                "recommendation": "Set X-Content-Type-Options: nosniff.",
            },
            "frame-ancestors": {
                "weight": 15,
                "recommendation": "Set CSP frame-ancestors or X-Frame-Options.",
            },
            "referrer-policy": {
                "weight": 10,
                "recommendation": "Set an explicit Referrer-Policy.",
            },
            "permissions-policy": {
                "weight": 10,
                "recommendation": "Restrict unneeded browser features with Permissions-Policy.",
            },
            "cross-origin-opener-policy": {
                "weight": 5,
                "recommendation": "Consider Cross-Origin-Opener-Policy for document isolation.",
            },
        }
        findings: list[dict[str, Any]] = []
        earned = 0
        possible = sum(control["weight"] for control in controls.values())
        for header, control in controls.items():
            if header == "frame-ancestors":
                present = "frame-ancestors" in headers.get(
                    "content-security-policy", ""
                ).lower() or ("x-frame-options" in headers)
                value = headers.get("x-frame-options")
            else:
                present = header in headers
                value = headers.get(header)
            if present:
                earned += control["weight"]
            elif control["weight"]:
                findings.append(
                    {
                        "severity": "low",
                        "header": header,
                        "issue": "missing",
                        "recommendation": control["recommendation"],
                    }
                )
            controls[header] = {"present": present, "value": value, **control}

        csp = headers.get("content-security-policy", "").lower()
        if csp and ("'unsafe-inline'" in csp or "*" in csp):
            findings.append(
                {
                    "severity": "medium",
                    "header": "content-security-policy",
                    "issue": "policy contains unsafe-inline or a wildcard source",
                }
            )
        disclosures = {key: headers[key] for key in ["server", "x-powered-by"] if key in headers}
        return {
            "url": response.final_url,
            "status": response.status,
            "score": round((earned / possible) * 100) if possible else 100,
            "controls": controls,
            "findings": findings,
            "information_disclosure": disclosures,
        }

    async def cors_scan(
        self,
        url: str,
        origins: list[str] | None = None,
    ) -> dict[str, Any]:
        test_origins = origins or ["https://example.invalid", "null"]
        tests = []
        findings = []
        for origin in test_origins:
            if origin != "null":
                split_origin = urlsplit(origin)
                if (
                    split_origin.scheme not in {"http", "https"}
                    or split_origin.hostname is None
                    or split_origin.username is not None
                    or split_origin.password is not None
                    or split_origin.path not in {"", "/"}
                    or split_origin.query
                    or split_origin.fragment
                    or not origin.isascii()
                    or any(ord(character) < 33 for character in origin)
                ):
                    raise ValueError(
                        "CORS origins must be null or absolute HTTP(S) origins without paths"
                    )
            response = await self._fetch(
                url,
                headers={"Origin": origin},
                follow_redirects=False,
            )
            allowed = response.headers.get("access-control-allow-origin")
            credentials = response.headers.get("access-control-allow-credentials", "").lower()
            tests.append(
                {
                    "origin": origin,
                    "status": response.status,
                    "allow_origin": allowed,
                    "allow_credentials": credentials,
                    "vary": response.headers.get("vary"),
                }
            )
            if allowed == origin and credentials == "true":
                findings.append(
                    {
                        "severity": "high",
                        "issue": "arbitrary origin reflected while credentials are allowed",
                        "origin": origin,
                    }
                )
            elif allowed == origin:
                findings.append(
                    {
                        "severity": "medium",
                        "issue": "test origin reflected",
                        "origin": origin,
                    }
                )
            elif allowed == "*" and credentials == "true":
                findings.append(
                    {
                        "severity": "medium",
                        "issue": (
                            "wildcard origin combined with credentials; browsers reject "
                            "this but it is misconfigured"
                        ),
                    }
                )
        return {"url": url, "tests": tests, "findings": findings}

    async def cookie_security_analysis(self, url: str) -> dict[str, Any]:
        response = await self._fetch(url)
        cookies = []
        for raw_cookie in response.set_cookies:
            parsed = SimpleCookie()
            try:
                parsed.load(raw_cookie)
            except Exception:  # SimpleCookie raises several parsing exception types.
                cookies.append(
                    {
                        "parse_error": True,
                        "header_sha256": stable_hash(raw_cookie),
                        "header_length": len(raw_cookie),
                    }
                )
                continue
            raw_lower = raw_cookie.lower()
            for name, morsel in parsed.items():
                issues = []
                secure = "; secure" in raw_lower
                http_only = "; httponly" in raw_lower
                same_site = morsel["samesite"] or None
                if not secure:
                    issues.append("missing Secure")
                if not http_only:
                    issues.append("missing HttpOnly")
                if not same_site:
                    issues.append("missing SameSite")
                if same_site and same_site.lower() == "none" and not secure:
                    issues.append("SameSite=None without Secure")
                cookies.append(
                    {
                        "name": name,
                        "secure": secure,
                        "http_only": http_only,
                        "same_site": same_site,
                        "path": morsel["path"] or None,
                        "domain": morsel["domain"] or None,
                        "issues": issues,
                    }
                )
        return {
            "url": response.final_url,
            "status": response.status,
            "cookies": cookies,
            "cookie_count": len(cookies),
        }

    async def security_txt_analysis(self, url: str) -> dict[str, Any]:
        parsed = await self.scope.require_network_safe(url, require_url=True)
        split = urlsplit(parsed.normalized or url)
        origin = f"{split.scheme}://{split.netloc}"
        candidates = [f"{origin}/.well-known/security.txt", f"{origin}/security.txt"]
        attempts: list[dict[str, Any]] = []
        selected: HTTPResponse | None = None
        for candidate in candidates:
            try:
                response = await self._fetch(candidate)
            except ToolExecutionError as exc:
                attempts.append({"url": candidate, "error": str(exc)})
                continue
            attempts.append({"url": candidate, "status": response.status})
            if response.status == 200 and response.body:
                selected = response
                break
        if selected is None:
            return {
                "origin": origin,
                "present": False,
                "attempts": attempts,
                "findings": [
                    {
                        "severity": "info",
                        "issue": "security.txt was not found at either conventional location",
                    }
                ],
            }

        content = selected.body.decode("utf-8", errors="replace")
        fields: dict[str, list[str]] = {}
        malformed_lines = 0
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                malformed_lines += 1
                continue
            name, value = line.split(":", 1)
            normalized_name = name.strip().lower()
            if not re.fullmatch(r"[a-z][a-z-]{0,63}", normalized_name) or not value.strip():
                malformed_lines += 1
                continue
            fields.setdefault(normalized_name, []).append(value.strip()[:2048])

        findings: list[dict[str, str]] = []
        if not fields.get("contact"):
            findings.append({"severity": "medium", "issue": "required Contact field is missing"})
        if not fields.get("expires"):
            findings.append({"severity": "medium", "issue": "required Expires field is missing"})
        else:
            try:
                expires = datetime.fromisoformat(fields["expires"][0].replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    raise ValueError("Expires must include a timezone")
                if expires < datetime.now(timezone.utc):
                    findings.append({"severity": "medium", "issue": "security.txt has expired"})
            except ValueError:
                findings.append({"severity": "medium", "issue": "Expires is not valid RFC 3339"})
        if selected.final_url != candidates[0]:
            findings.append(
                {
                    "severity": "info",
                    "issue": "security.txt was not served from the preferred /.well-known path",
                }
            )
        if malformed_lines:
            findings.append(
                {
                    "severity": "low",
                    "issue": f"{malformed_lines} non-comment line(s) were malformed",
                }
            )
        return {
            "origin": origin,
            "present": True,
            "url": selected.final_url,
            "content_sha256": stable_hash(selected.body),
            "body_truncated": selected.truncated,
            "fields": fields,
            "attempts": attempts,
            "findings": findings,
        }

    async def openapi_discovery(
        self,
        url: str,
        paths: list[str] | None = None,
    ) -> dict[str, Any]:
        base = await self.scope.require_network_safe(url, require_url=True)
        candidates = paths or _OPENAPI_PATHS
        base_parts = urlsplit(base.normalized or url)
        origin = f"{base_parts.scheme}://{base_parts.netloc}/"
        documents: list[dict[str, Any]] = []
        attempts: list[dict[str, Any]] = []
        for path in candidates:
            if "://" in path:
                raise ValueError(
                    "OpenAPI candidate paths must be relative to the authorized origin"
                )
            candidate_url = urljoin(origin, quote(path.lstrip("/"), safe="/._~-"))
            try:
                response = await self._fetch(candidate_url, follow_redirects=True)
            except ToolExecutionError as exc:
                attempts.append({"url": candidate_url, "error": str(exc)})
                continue
            attempts.append({"url": candidate_url, "status": response.status})
            if response.status != 200 or not response.body or response.truncated:
                continue
            text = response.body.decode("utf-8", errors="replace")
            document: Any
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                try:
                    # This loader subclasses SafeLoader and additionally forbids aliases.
                    document = yaml.load(text, Loader=_NoAliasSafeLoader)  # noqa: S506
                except yaml.YAMLError:
                    continue
            if not isinstance(document, dict):
                continue
            _bounded_structure_size(document)
            version = document.get("openapi") or document.get("swagger")
            api_paths = document.get("paths")
            if not version or not isinstance(api_paths, dict):
                continue
            method_count = sum(
                key.lower() in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
                for path_item in api_paths.values()
                if isinstance(path_item, dict)
                for key in path_item
                if isinstance(key, str)
            )
            raw_info = document.get("info")
            info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            documents.append(
                {
                    "url": response.final_url,
                    "format_version": str(version)[:50],
                    "title": str(info.get("title", ""))[:300] or None,
                    "api_version": str(info.get("version", ""))[:100] or None,
                    "path_count": len(api_paths),
                    "operation_count": method_count,
                    "content_sha256": stable_hash(response.body),
                }
            )
        return {
            "base_url": origin,
            "documents": documents,
            "document_count": len(documents),
            "attempts": attempts,
        }

    async def ssl_scan(self, target: str, port: int = 443) -> dict[str, Any]:
        parsed, addresses = await self.scope.resolve_network_safe(target)
        host = parsed.host
        port = parsed.port or port

        def inspect() -> dict[str, Any]:
            connection_error: OSError | None = None
            selected_address: str | None = None
            der: bytes | None = None
            protocol: str | None = None
            cipher: tuple[str, str, int] | None = None
            unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified_context.check_hostname = False
            unverified_context.verify_mode = ssl.CERT_NONE
            for address in addresses:
                try:
                    with socket.create_connection(
                        (address, port), timeout=self.config.scanning.request_timeout
                    ) as raw_socket:
                        with unverified_context.wrap_socket(
                            raw_socket, server_hostname=host
                        ) as tls_socket:
                            der = tls_socket.getpeercert(binary_form=True)
                            protocol = tls_socket.version()
                            cipher = tls_socket.cipher()
                            selected_address = address
                            break
                except OSError as exc:
                    connection_error = exc

            if selected_address is None:
                raise connection_error or OSError("no validated address accepted a TLS connection")
            if der is None:
                raise ValueError("TLS peer did not provide a certificate")
            certificate = x509.load_der_x509_certificate(der)
            try:
                sans = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []

            verified = True
            verification_error = None
            try:
                verified_context = ssl.create_default_context()
                with socket.create_connection(
                    (selected_address, port), timeout=self.config.scanning.request_timeout
                ) as raw_socket:
                    with verified_context.wrap_socket(raw_socket, server_hostname=host):
                        pass
            except (OSError, ssl.SSLError) as exc:
                verified = False
                verification_error = str(exc)

            now = datetime.now(timezone.utc)
            expires = certificate.not_valid_after_utc
            return {
                "target": host,
                "connected_address": selected_address,
                "port": port,
                "protocol": protocol,
                "cipher": {
                    "name": cipher[0] if cipher else None,
                    "protocol": cipher[1] if cipher else None,
                    "bits": cipher[2] if cipher else None,
                },
                "certificate": {
                    "subject": certificate.subject.rfc4514_string(),
                    "issuer": certificate.issuer.rfc4514_string(),
                    "serial_number": format(certificate.serial_number, "x"),
                    "not_before": certificate.not_valid_before_utc.isoformat(),
                    "not_after": expires.isoformat(),
                    "days_until_expiry": (expires - now).days,
                    "expired": expires < now,
                    "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
                    "dns_names": sorted(sans),
                },
                "trusted_for_host": verified,
                "verification_error": verification_error,
            }

        try:
            return await asyncio.to_thread(inspect)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise ToolExecutionError(
                f"TLS inspection failed: {exc.__class__.__name__}: {exc}", code="tls_error"
            ) from exc

    async def port_scan(self, target: str, ports: str | None = None) -> dict[str, Any]:
        parsed, addresses = await self.scope.resolve_network_safe(target)
        selected = parse_ports(
            ports,
            self.config.scanning.default_ports,
            self.config.scanning.max_ports_per_scan,
        )

        async def scan(port: int) -> dict[str, Any] | None:
            started = asyncio.get_running_loop().time()
            for address in addresses:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(address, port),
                        timeout=self.config.scanning.connect_timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return {
                        "port": port,
                        "address": address,
                        "service_hint": _SERVICE_NAMES.get(port, "unknown"),
                        "latency_ms": round(
                            (asyncio.get_running_loop().time() - started) * 1000,
                            2,
                        ),
                    }
                except (TimeoutError, OSError):
                    continue
            return None

        results = await bounded_map(
            selected,
            scan,
            concurrency=self.config.scanning.max_concurrency,
        )
        open_ports = [result for result in results if result is not None]
        return {
            "target": parsed.host,
            "scanned_at": utc_now(),
            "ports_scanned": len(selected),
            "open_ports": open_ports,
            "open_count": len(open_ports),
            "scan_type": "tcp_connect",
        }

    async def web_crawler(
        self,
        url: str,
        max_pages: int | None = None,
        max_depth: int | None = None,
    ) -> dict[str, Any]:
        start = await self.scope.require_network_safe(url, require_url=True)
        page_limit = min(
            max_pages or self.config.scanning.max_pages_to_crawl,
            self.config.scanning.max_pages_to_crawl,
        )
        depth_limit = min(
            max_depth if max_depth is not None else self.config.scanning.max_crawl_depth,
            self.config.scanning.max_crawl_depth,
        )
        queue: deque[tuple[str, int]] = deque([(start.normalized or url, 0)])
        seen: set[str] = set()
        pages: list[dict[str, Any]] = []
        discovered: set[str] = set()
        forms: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        discovered_limit = min(
            page_limit * self.config.scanning.max_links_per_page,
            50_000,
        )
        form_limit = min(
            page_limit * self.config.scanning.max_forms_per_page,
            10_000,
        )
        inventory_truncated = False

        while queue and len(pages) < page_limit:
            current, depth = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            try:
                response = await self._fetch(current)
            except ToolExecutionError as exc:
                errors.append({"url": current, "error": str(exc)})
                continue
            inspector = self._inspect_html(response)
            pages.append(
                {
                    "url": response.final_url,
                    "status": response.status,
                    "title": inspector.title,
                    "content_type": response.content_type,
                    "depth": depth,
                    "links_truncated": inspector.links_truncated,
                    "forms_truncated": inspector.forms_truncated,
                }
            )
            for form in inspector.forms:
                if len(forms) < form_limit:
                    forms.append(
                        {
                            **form,
                            "page": response.final_url,
                            "action": urljoin(response.final_url, form["action"]),
                        }
                    )
                else:
                    inventory_truncated = True
            inventory_truncated |= inspector.links_truncated or inspector.forms_truncated
            if depth >= depth_limit:
                continue
            for raw_link in inspector.links:
                absolute = urljoin(response.final_url, raw_link)
                split = urlsplit(absolute)
                if split.scheme not in {"http", "https"} or split.hostname is None:
                    continue
                try:
                    candidate = parse_target(absolute, require_url=True)
                except ValueError:
                    continue
                if candidate.host != start.host:
                    continue
                normalized = candidate.normalized or absolute
                if normalized not in discovered and len(discovered) >= discovered_limit:
                    inventory_truncated = True
                    continue
                discovered.add(normalized)
                if normalized not in seen:
                    queue.append((normalized, depth + 1))

        return {
            "start_url": start.normalized,
            "crawled_at": utc_now(),
            "pages": pages,
            "page_count": len(pages),
            "discovered_urls": sorted(discovered),
            "forms": forms,
            "errors": errors,
            "inventory_truncated": inventory_truncated,
            "limits": {
                "max_pages": page_limit,
                "max_depth": depth_limit,
                "max_links_per_page": self.config.scanning.max_links_per_page,
                "max_forms_per_page": self.config.scanning.max_forms_per_page,
                "max_discovered_urls": discovered_limit,
                "max_forms": form_limit,
            },
        }

    async def web_directory_scan(
        self,
        url: str,
        paths: list[str] | None = None,
    ) -> dict[str, Any]:
        base = await self.scope.require_network_safe(url, require_url=True)
        candidates = list(paths or [])
        if not candidates and self.config.scanning.directory_wordlist:
            candidates = self._load_configured_wordlist(self.config.scanning.directory_wordlist)
        if not candidates:
            candidates = list(_COMMON_PATHS)
        request_limit = self.config.scanning.max_directory_requests
        if len(candidates) > request_limit:
            raise ValueError(f"path list exceeds the configured {request_limit}-request limit")

        async def probe(path: str) -> dict[str, Any]:
            target_url = urljoin(
                base.normalized or url, quote(path.strip().lstrip("/"), safe="/._~-")
            )
            try:
                response = await self._fetch(
                    target_url,
                    method="HEAD",
                    follow_redirects=False,
                )
                return {
                    "path": path,
                    "url": target_url,
                    "status": response.status,
                    "content_type": response.content_type,
                    "content_length": response.headers.get("content-length"),
                    "interesting": response.status not in {400, 404, 410},
                }
            except ToolExecutionError as exc:
                return {"path": path, "url": target_url, "error": str(exc), "interesting": False}

        results = await bounded_map(
            candidates,
            probe,
            concurrency=min(self.config.scanning.max_concurrency, 10),
        )
        return {
            "base_url": base.normalized,
            "requests": len(results),
            "results": [result for result in results if result.get("interesting")],
            "status_counts": dict(
                Counter(str(result.get("status", "error")) for result in results)
            ),
        }

    @staticmethod
    def _load_configured_wordlist(path: Path) -> list[str]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return [
                    line.strip()
                    for line in handle
                    if line.strip() and not line.lstrip().startswith("#")
                ]
        except OSError as exc:
            raise ValueError(f"configured directory wordlist is unreadable: {exc}") from exc

    async def jwt_security_test(self, jwt_token: str) -> dict[str, Any]:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT must contain exactly three dot-separated segments")

        def decode(segment: str) -> Any:
            padding = "=" * (-len(segment) % 4)
            try:
                decoded = base64.urlsafe_b64decode(segment + padding)
                return json.loads(decoded)
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError("JWT header or payload is not valid base64url JSON") from exc

        header = decode(parts[0])
        payload = decode(parts[1])
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("JWT header and payload must be JSON objects")
        findings = []
        algorithm = str(header.get("alg", "")).lower()
        if not algorithm or algorithm == "none":
            findings.append({"severity": "critical", "issue": "unsigned or unspecified algorithm"})
        elif algorithm.startswith("hs"):
            findings.append(
                {
                    "severity": "info",
                    "issue": "HMAC JWT; verify that a strong random shared secret is used",
                }
            )
        if "kid" in header:
            findings.append(
                {
                    "severity": "info",
                    "issue": (
                        "kid header is present; validate it cannot influence unsafe file/SQL lookup"
                    ),
                }
            )
        now = datetime.now(timezone.utc).timestamp()
        expiry = payload.get("exp")
        if isinstance(expiry, (int, float)) and expiry < now:
            findings.append({"severity": "medium", "issue": "token is expired"})
        if expiry is None:
            findings.append({"severity": "low", "issue": "token has no exp claim"})
        if "iss" not in payload:
            findings.append({"severity": "info", "issue": "token has no iss claim"})
        if "aud" not in payload:
            findings.append({"severity": "info", "issue": "token has no aud claim"})
        return {
            "header": header,
            "payload": payload,
            "signature_present": bool(parts[2]),
            "findings": findings,
            "warning": "The token was decoded but its signature was not verified.",
        }

    async def nuclei_scan(
        self,
        target: str,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        if not self.config.tools.enable_nuclei:
            raise ToolExecutionError(
                "Nuclei is disabled; set ENABLE_NUCLEI=true after reviewing its "
                "templates and rate limits",
                code="tool_disabled",
            )
        await self.scope.require_network_safe(target)
        binary = shutil.which(self.config.tools.nuclei_path)
        if binary is None:
            raise ToolExecutionError(
                f"Nuclei binary was not found: {self.config.tools.nuclei_path}",
                code="dependency_missing",
            )
        command = [
            binary,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-no-stdin",
            "-disable-update-check",
            "-no-interactsh",
            "-disable-redirects",
            "-exclude-tags",
            "dos,fuzz,code,headless",
            "-rate-limit",
            str(max(1, math.floor(self.config.requests_per_second))),
            "-concurrency",
            str(min(self.config.scanning.max_concurrency, 10)),
            "-bulk-size",
            "1",
            "-timeout",
            str(math.ceil(self.config.scanning.request_timeout)),
            "-response-size-read",
            str(self.config.scanning.max_response_bytes),
            "-response-size-save",
            str(self.config.scanning.max_response_bytes),
        ]
        if not self.config.allow_private_targets:
            command.append("-restrict-local-network-access")
        if severity:
            command.extend(["-severity", ",".join(severity)])
        if tags:
            command.extend(["-tags", ",".join(tags)])
        result = await run_command_async(
            command,
            timeout=min(self.config.tool_timeout, 900),
            max_output_bytes=10_000_000,
        )
        findings = []
        for line in result["stdout"].splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info") or {}
            findings.append(
                {
                    "template_id": item.get("template-id") or item.get("template_id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": item.get("matched-at") or item.get("matched_at"),
                    "type": item.get("type"),
                }
            )
        if not result["success"] and not findings:
            raise ToolExecutionError(
                f"Nuclei failed: {result['stderr'][:2000] or 'unknown error'}",
                code="external_tool_failed",
            )
        return {
            "target": target,
            "findings": findings,
            "finding_count": len(findings),
            "by_severity": dict(Counter(item.get("severity") or "unknown" for item in findings)),
            "process": {
                "returncode": result["returncode"],
                "timed_out": result["timed_out"],
                "output_truncated": result["stdout_truncated"] or result["stderr_truncated"],
            },
        }

    async def create_finding(
        self,
        title: str,
        severity: str,
        target: str,
        description: str,
        evidence: str | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
        impact: str | None = None,
        steps_to_reproduce: list[str] | None = None,
        cwe: str | None = None,
        cvss_score: float | None = None,
        confidence: str = "firm",
        tags: list[str] | None = None,
        source_tool: str | None = None,
    ) -> dict[str, Any]:
        finding = await self.findings.create(
            title=title,
            severity=severity,
            target=target,
            description=description,
            evidence=evidence,
            remediation=remediation,
            references=references,
            impact=impact,
            steps_to_reproduce=steps_to_reproduce,
            cwe=cwe,
            cvss_score=cvss_score,
            confidence=confidence,
            tags=tags,
            source_tool=source_tool,
        )
        return {"finding": finding}

    async def add_finding_evidence(
        self,
        finding_id: str,
        label: str,
        content: str,
        media_type: str = "text/plain",
    ) -> dict[str, Any]:
        artifact = await self.findings.add_evidence(
            finding_id,
            label=label,
            content=content,
            media_type=media_type,
        )
        return {"evidence": artifact}

    async def list_findings(
        self,
        target: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        findings = await self.findings.list(target=target, severity=severity, status=status)
        return {"findings": findings, "count": len(findings)}

    async def update_finding(
        self,
        finding_id: str,
        status: str,
        remediation: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        finding = await self.findings.update(
            finding_id,
            status=status,
            remediation=remediation,
            note=note,
        )
        return {"finding": finding}

    async def generate_vulnerability_report(
        self,
        report_format: str = "json",
        target: str | None = None,
    ) -> dict[str, Any]:
        return await self.findings.report(format=report_format, target=target)

    async def assessment_summary(self) -> dict[str, Any]:
        return {
            "generated_at": utc_now(),
            "scope": {
                "safe_mode": self.config.safe_mode,
                "configured": bool(self.config.allowed_targets),
                "allowed_target_count": len(self.config.allowed_targets),
                "blocked_target_count": len(self.config.blocked_targets),
                "private_targets_enabled": self.config.allow_private_targets,
            },
            "findings": await self.findings.summary(),
            "runtime": self.metrics_snapshot(),
        }

    def metrics_snapshot(self) -> dict[str, Any]:
        calls = self._metrics["calls"]
        return {
            "started_at": self._started_at,
            "active_calls": self._active_calls,
            "calls": calls,
            "succeeded": self._metrics["succeeded"],
            "rejected": self._metrics["rejected"],
            "failed": self._metrics["failed"],
            "cancelled": self._metrics["cancelled"],
            "average_duration_ms": (
                round(self._metrics["duration_ms_total"] / calls, 2) if calls else 0
            ),
            "per_tool": dict(sorted(self._per_tool_calls.items())),
        }

    async def server_health(self) -> dict[str, Any]:
        nuclei_binary = shutil.which(self.config.tools.nuclei_path)
        return {
            "status": "ok",
            "version": __version__,
            "time": utc_now(),
            "safe_mode": self.config.safe_mode,
            "scope_configured": bool(self.config.allowed_targets),
            "allowed_target_count": len(self.config.allowed_targets),
            "private_targets_enabled": self.config.allow_private_targets,
            "tools": len(self._specs),
            "runtime": self.metrics_snapshot(),
            "nuclei": {
                "enabled": self.config.tools.enable_nuclei,
                "available": nuclei_binary is not None,
            },
            "storage": {
                "data_dir": str(self.config.output.data_dir),
                "output_dir": str(self.config.output.output_dir),
            },
        }
