"""Pure, bounded analyzers shared by the MCP security tools."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import yaml

from ..utils import stable_hash

_MAX_ANALYZER_ITEMS = 500
_SECURITY_PARAMETER_GROUPS = {
    "redirect": {
        "continue",
        "dest",
        "destination",
        "next",
        "redirect",
        "redirect_to",
        "redirect_uri",
        "return",
        "return_to",
        "returnurl",
        "url",
    },
    "authentication": {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "code",
        "id_token",
        "jwt",
        "key",
        "password",
        "secret",
        "session",
        "token",
    },
    "object_reference": {
        "account",
        "doc",
        "document",
        "file",
        "id",
        "invoice",
        "order",
        "profile",
        "project",
        "tenant",
        "user",
        "userid",
    },
    "file_or_path": {
        "dir",
        "directory",
        "download",
        "filename",
        "folder",
        "include",
        "page",
        "path",
        "template",
        "upload",
    },
    "query_or_command": {
        "cmd",
        "command",
        "exec",
        "filter",
        "q",
        "query",
        "search",
        "sort",
        "where",
    },
}
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "aws_access_key_id",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "high",
    ),
    (
        "github_token",
        re.compile(r"(?<![A-Za-z0-9_])gh(?:p|o|u|s|r)_[A-Za-z0-9_]{20,255}"),
        "high",
    ),
    (
        "gitlab_token",
        re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}"),
        "high",
    ),
    (
        "slack_token",
        re.compile(r"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,255}"),
        "high",
    ),
    (
        "google_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
        "high",
    ),
    (
        "stripe_live_key",
        re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{16,255}"),
        "high",
    ),
    (
        "jwt",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
        "medium",
    ),
    (
        "private_key_marker",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "critical",
    ),
)
_CLOUD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws_s3",
        re.compile(
            r"https?://(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.)?s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?",
            re.I,
        ),
    ),
    (
        "aws_s3_virtual_host",
        re.compile(
            r"https?://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?",
            re.I,
        ),
    ),
    (
        "google_cloud_storage",
        re.compile(
            r"https?://storage\.googleapis\.com/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+",
            re.I,
        ),
    ),
    (
        "azure_blob_storage",
        re.compile(
            r"https?://[a-z0-9][a-z0-9-]{1,62}\.blob\.core\.windows\.net(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?",
            re.I,
        ),
    ),
    (
        "firebase",
        re.compile(
            r"https?://[a-z0-9-]+\.(?:firebaseio\.com|web\.app)(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?",
            re.I,
        ),
    ),
)
_JS_ENDPOINT_PATTERN = re.compile(
    r"(?P<quote>['\"])(?P<value>(?:https?://|wss?://|/|\./|\.\./)[^'\"\s<>]{1,500})(?P=quote)"
)
_CVSS_METRICS: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


class _NoAliasSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that additionally rejects aliases."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not accepted")
        return super().compose_node(parent, index)


def bounded_structure_size(value: Any, *, maximum: int = 100_000) -> int:
    """Count decoded nodes without recursion and reject oversized documents."""
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


def load_structured_document(content: str, document_format: str = "auto") -> Any:
    """Load bounded JSON or alias-free safe YAML."""
    if len(content.encode("utf-8")) > 1_000_000:
        raise ValueError("document exceeds the 1,000,000-byte analysis limit")
    try:
        if document_format == "json":
            document = json.loads(content)
        elif document_format == "yaml":
            document = yaml.load(content, Loader=_NoAliasSafeLoader)  # noqa: S506
        else:
            try:
                document = json.loads(content)
            except json.JSONDecodeError:
                document = yaml.load(content, Loader=_NoAliasSafeLoader)  # noqa: S506
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"document is not valid {document_format}: {exc}") from exc
    bounded_structure_size(document)
    return document


def generate_domain_variants(domain: str, *, maximum: int) -> list[dict[str, str]]:
    """Generate deterministic, typo-oriented variants without resolving them."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        raise ValueError("domain variation generation requires a dotted domain name")
    label = labels[0]
    suffix = ".".join(labels[1:])
    generated: dict[str, str] = {}

    def add(candidate: str, kind: str) -> None:
        if (
            candidate != label
            and 0 < len(candidate) <= 63
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", candidate)
        ):
            generated.setdefault(f"{candidate}.{suffix}", kind)

    for index in range(len(label)):
        add(label[:index] + label[index + 1 :], "omission")
        add(label[:index] + label[index] + label[index:], "duplication")
    for index in range(len(label) - 1):
        if label[index] != label[index + 1]:
            add(
                label[:index] + label[index + 1] + label[index] + label[index + 2 :],
                "transposition",
            )
    for index in range(1, len(label)):
        add(label[:index] + "-" + label[index:], "hyphenation")
    keyboard_neighbors = {
        "a": "qwsz",
        "e": "wsdr",
        "i": "ujko",
        "o": "iklp",
        "u": "yhji",
    }
    for index, character in enumerate(label):
        for replacement in keyboard_neighbors.get(character, ""):
            add(label[:index] + replacement + label[index + 1 :], "keyboard_neighbor")

    return [
        {"domain": candidate, "variation": kind}
        for candidate, kind in sorted(generated.items())[:maximum]
    ]


def analyze_url_parameters(url: str) -> dict[str, Any]:
    """Inventory URL parameters without echoing their potentially sensitive values."""
    split = urlsplit(url)
    if split.scheme not in {"http", "https"} or split.hostname is None:
        raise ValueError("url must be an absolute HTTP(S) URL")
    pairs = parse_qsl(split.query, keep_blank_values=True, strict_parsing=False)
    if len(pairs) > 200:
        raise ValueError("URL contains more than 200 query parameters")
    counts = Counter(name for name, _value in pairs)
    parameters = []
    categories: Counter[str] = Counter()
    for name, value in pairs:
        normalized_name = name.lower().replace("-", "_")
        matched_categories = sorted(
            category
            for category, names in _SECURITY_PARAMETER_GROUPS.items()
            if normalized_name in names
        )
        categories.update(matched_categories)
        decoded = unquote(value)
        parameters.append(
            {
                "name": name[:200],
                "categories": matched_categories,
                "duplicate": counts[name] > 1,
                "blank": value == "",
                "value_length": len(value),
                "value_sha256": stable_hash(value),
                "contains_absolute_url": bool(re.search(r"https?://", decoded, re.I)),
                "encoded_layers": int(decoded != value) + int(unquote(decoded) != decoded),
            }
        )
    return {
        "url": f"{split.scheme}://{split.netloc}{split.path}",
        "parameter_count": len(parameters),
        "unique_parameter_count": len(counts),
        "parameters": parameters,
        "category_counts": dict(sorted(categories.items())),
        "fragment_present": bool(split.fragment),
    }


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def analyze_secret_patterns(content: str, *, maximum: int = 200) -> dict[str, Any]:
    """Find credential patterns while returning only hashes and locations."""
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for kind, pattern, severity in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            key = (kind, match.start(), match.end())
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "kind": kind,
                    "severity": severity,
                    "line": _line_number(content, match.start()),
                    "start": match.start(),
                    "length": match.end() - match.start(),
                    "fingerprint": stable_hash(match.group(0))[:16],
                }
            )
            if len(matches) >= maximum:
                break
        if len(matches) >= maximum:
            break
    matches.sort(key=lambda item: (item["start"], item["kind"]))
    return {
        "content_sha256": stable_hash(content),
        "content_length": len(content),
        "matches": matches,
        "match_count": len(matches),
        "truncated": len(matches) >= maximum,
        "values_redacted": True,
        "by_kind": dict(Counter(item["kind"] for item in matches)),
    }


def analyze_cloud_references(content: str, *, maximum: int = _MAX_ANALYZER_ITEMS) -> dict[str, Any]:
    """Extract cloud asset references from supplied text without accessing them."""
    references: dict[str, str] = {}
    for provider, pattern in _CLOUD_PATTERNS:
        for match in pattern.finditer(content):
            references.setdefault(match.group(0).rstrip(".,;)\"'"), provider)
            if len(references) >= maximum:
                break
        if len(references) >= maximum:
            break
    items = [
        {"provider": provider, "reference": reference}
        for reference, provider in sorted(references.items())
    ]
    return {
        "content_sha256": stable_hash(content),
        "references": items,
        "reference_count": len(items),
        "truncated": len(references) >= maximum,
        "by_provider": dict(Counter(item["provider"] for item in items)),
    }


def analyze_csp(policy: str) -> dict[str, Any]:
    """Parse a CSP header and flag broadly unsafe or obsolete directives."""
    directives: dict[str, list[str]] = {}
    duplicates: list[str] = []
    for raw_directive in policy.split(";"):
        parts = raw_directive.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in directives:
            duplicates.append(name)
            continue
        directives[name] = parts[1:]

    findings: list[dict[str, str]] = []
    if not directives.get("default-src"):
        findings.append({"severity": "medium", "issue": "default-src is missing"})
    for directive in ("script-src", "script-src-elem", "default-src"):
        sources = directives.get(directive, [])
        if "'unsafe-eval'" in sources:
            findings.append({"severity": "high", "issue": f"{directive} allows unsafe-eval"})
        if "'unsafe-inline'" in sources:
            findings.append({"severity": "medium", "issue": f"{directive} allows unsafe-inline"})
        if "*" in sources:
            findings.append({"severity": "medium", "issue": f"{directive} allows wildcard sources"})
        if any(source.lower().startswith("data:") for source in sources):
            findings.append({"severity": "low", "issue": f"{directive} allows data: sources"})
    object_sources = directives.get("object-src")
    if object_sources != ["'none'"]:
        findings.append({"severity": "medium", "issue": "object-src is not explicitly 'none'"})
    if "base-uri" not in directives:
        findings.append({"severity": "low", "issue": "base-uri is missing"})
    if "frame-ancestors" not in directives:
        findings.append({"severity": "low", "issue": "frame-ancestors is missing"})
    if "report-uri" in directives:
        findings.append({"severity": "info", "issue": "report-uri is deprecated; prefer report-to"})
    for duplicate in sorted(set(duplicates)):
        findings.append({"severity": "medium", "issue": f"duplicate {duplicate} directive"})
    return {
        "policy_sha256": stable_hash(policy),
        "directives": directives,
        "directive_count": len(directives),
        "findings": findings,
        "finding_count": len(findings),
    }


def parse_robots(content: str) -> dict[str, Any]:
    """Parse a bounded robots.txt summary using RFC 9309 field syntax."""
    groups: list[dict[str, Any]] = []
    current_agents: list[str] = []
    current_rules: list[dict[str, str]] = []
    sitemaps: list[str] = []
    malformed = 0

    def flush() -> None:
        nonlocal current_agents, current_rules
        if current_agents:
            groups.append({"user_agents": current_agents, "rules": current_rules})
        current_agents = []
        current_rules = []

    for raw_line in content.splitlines()[:10_000]:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            malformed += 1
            continue
        field, value = (part.strip() for part in line.split(":", 1))
        field = field.lower()
        if field == "user-agent":
            if current_rules:
                flush()
            if value:
                current_agents.append(value[:200])
        elif field in {"allow", "disallow"}:
            if not current_agents:
                malformed += 1
            else:
                current_rules.append({"directive": field, "path": value[:2000]})
        elif field == "sitemap" and value:
            sitemaps.append(value[:2048])
    flush()
    return {
        "groups": groups[:500],
        "group_count": len(groups),
        "rule_count": sum(len(group["rules"]) for group in groups),
        "sitemaps": list(dict.fromkeys(sitemaps))[:100],
        "malformed_lines": malformed,
        "truncated": len(content.splitlines()) > 10_000 or len(groups) > 500,
    }


def extract_javascript_endpoints(content: str, *, maximum: int = 1000) -> dict[str, Any]:
    """Extract literal HTTP, WebSocket, and path references from JavaScript/text."""
    endpoints: dict[str, str] = {}
    for match in _JS_ENDPOINT_PATTERN.finditer(content):
        value = match.group("value")
        if value.startswith("//") or "${" in value or "{" in value:
            continue
        kind = "absolute" if re.match(r"^(?:https?|wss?)://", value, re.I) else "relative"
        endpoints.setdefault(value, kind)
        if len(endpoints) >= maximum:
            break
    items = [{"value": value, "kind": kind} for value, kind in sorted(endpoints.items())]
    return {
        "content_sha256": stable_hash(content),
        "endpoints": items,
        "endpoint_count": len(items),
        "truncated": len(endpoints) >= maximum,
    }


def analyze_openapi_document(document: Any) -> dict[str, Any]:
    """Summarize authentication and operation-level OpenAPI security posture."""
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document root must be an object")
    version = document.get("openapi") or document.get("swagger")
    paths = document.get("paths")
    if not version or not isinstance(paths, dict):
        raise ValueError("document does not contain an OpenAPI/Swagger version and paths object")

    components = document.get("components") if isinstance(document.get("components"), dict) else {}
    security_schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    if not isinstance(security_schemes, dict):
        security_schemes = {}
    global_security = document.get("security")
    methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    operations: list[dict[str, Any]] = []
    unauthenticated: list[dict[str, str]] = []
    deprecated: list[dict[str, str]] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        for raw_method, operation in path_item.items():
            if not isinstance(raw_method, str) or raw_method.lower() not in methods:
                continue
            operation = operation if isinstance(operation, dict) else {}
            security = operation.get("security", global_security)
            item = {
                "path": raw_path[:1000],
                "method": raw_method.upper(),
                "operation_id": str(operation.get("operationId", ""))[:300] or None,
                "deprecated": operation.get("deprecated") is True,
                "security_defined": bool(security),
            }
            operations.append(item)
            if security == [] or security is None:
                unauthenticated.append({"path": raw_path[:1000], "method": raw_method.upper()})
            if item["deprecated"]:
                deprecated.append({"path": raw_path[:1000], "method": raw_method.upper()})
            if len(operations) >= 10_000:
                break
        if len(operations) >= 10_000:
            break

    servers = document.get("servers", [])
    server_urls = []
    if isinstance(servers, list):
        server_urls = [
            str(server.get("url"))[:2048]
            for server in servers[:100]
            if isinstance(server, dict) and server.get("url")
        ]
    findings: list[dict[str, Any]] = []
    if not security_schemes:
        findings.append({"severity": "medium", "issue": "no security schemes are declared"})
    if unauthenticated:
        findings.append(
            {
                "severity": "info",
                "issue": (
                    f"{len(unauthenticated)} operation(s) have no effective security requirement"
                ),
            }
        )
    if any(item["method"] == "TRACE" for item in operations):
        findings.append({"severity": "low", "issue": "TRACE operations are documented"})
    return {
        "format_version": str(version)[:50],
        "path_count": len(paths),
        "operation_count": len(operations),
        "operations": operations,
        "operations_truncated": len(operations) >= 10_000,
        "security_schemes": sorted(str(name)[:200] for name in security_schemes)[:500],
        "unauthenticated_operations": unauthenticated[:1000],
        "deprecated_operations": deprecated[:1000],
        "server_urls": server_urls,
        "findings": findings,
        "finding_count": len(findings),
    }


def _roundup(value: float) -> float:
    return math.ceil((value - 1e-10) * 10) / 10


def calculate_cvss_v31(vector: str) -> dict[str, Any]:
    """Calculate a CVSS v3.1 base score from the eight mandatory base metrics."""
    normalized = vector.strip().upper()
    if normalized.startswith("CVSS:3.1/"):
        normalized = normalized[len("CVSS:3.1/") :]
    metrics: dict[str, str] = {}
    for component in normalized.split("/"):
        if ":" not in component:
            raise ValueError("CVSS vector components must use METRIC:VALUE syntax")
        metric, value = component.split(":", 1)
        if metric not in _CVSS_METRICS or value not in _CVSS_METRICS[metric]:
            raise ValueError(f"invalid CVSS v3.1 base metric: {component}")
        if metric in metrics:
            raise ValueError(f"duplicate CVSS metric: {metric}")
        metrics[metric] = value
    missing = sorted(set(_CVSS_METRICS) - set(metrics))
    if missing:
        raise ValueError("CVSS vector is missing metrics: " + ", ".join(missing))

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    scope_changed = metrics["S"] == "C"
    pr_values = (
        {"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27}
    )
    pr = pr_values[metrics["PR"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    impacts = {"N": 0.0, "L": 0.22, "H": 0.56}
    confidentiality = impacts[metrics["C"]]
    integrity = impacts[metrics["I"]]
    availability = impacts[metrics["A"]]
    impact_subscore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)
    else:
        impact = 6.42 * impact_subscore
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    rating = (
        "none"
        if score == 0
        else "low"
        if score < 4
        else "medium"
        if score < 7
        else "high"
        if score < 9
        else "critical"
    )
    canonical = "CVSS:3.1/" + "/".join(f"{metric}:{metrics[metric]}" for metric in _CVSS_METRICS)
    return {
        "vector": canonical,
        "base_score": score,
        "rating": rating,
        "impact_subscore": round(max(impact, 0), 4),
        "exploitability_subscore": round(exploitability, 4),
        "metrics": metrics,
    }
