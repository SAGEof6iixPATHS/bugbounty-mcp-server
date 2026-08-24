"""Canonical target parsing and fail-closed authorization checks."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, urlsplit, urlunsplit

if TYPE_CHECKING:
    from .config import BugBountyConfig


_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeViolation(ValueError):
    """Raised when a target is invalid or outside the configured authorization scope."""


@dataclass(frozen=True, slots=True)
class ParsedTarget:
    original: str
    host: str
    kind: str
    port: int | None = None
    scheme: str | None = None
    normalized: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: str
    target: ParsedTarget | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "target": self.target.to_dict() if self.target else None,
        }


def _normalize_host(host: str) -> tuple[str, str]:
    value = host.strip().rstrip(".").lower()
    if not value or any(ord(character) < 33 for character in value):
        raise ValueError("target host is empty or contains control characters")
    try:
        address = ipaddress.ip_address(value)
        return address.compressed, "ip"
    except ValueError:
        pass

    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target contains an invalid internationalized domain") from exc
    if len(ascii_host) > 253:
        raise ValueError("domain is longer than 253 characters")
    labels = ascii_host.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("target is not a valid IP address or domain")
    return ascii_host, "domain"


def parse_target(target: str, *, require_url: bool = False) -> ParsedTarget:
    """Parse a URL, domain, or IP without resolving it."""
    raw = target.strip()
    if not raw:
        raise ValueError("target cannot be empty")

    has_scheme = "://" in raw
    if require_url and not has_scheme:
        raise ValueError("an absolute http:// or https:// URL is required")

    if has_scheme:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("only http:// and https:// targets are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("credentials in target URLs are not allowed")
        if parsed.hostname is None:
            raise ValueError("URL does not contain a host")
        host, kind = _normalize_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("URL contains an invalid port") from exc
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        normalized_netloc = f"[{host}]" if ":" in host else host
        if port is not None and port != default_port:
            normalized_netloc = f"{normalized_netloc}:{port}"
        normalized = urlunsplit(
            SplitResult(
                parsed.scheme.lower(),
                normalized_netloc,
                parsed.path or "/",
                parsed.query,
                "",
            )
        )
        return ParsedTarget(
            original=target,
            host=host,
            kind=kind,
            port=port or default_port,
            scheme=parsed.scheme.lower(),
            normalized=normalized,
        )

    # urlsplit with // correctly handles bracketed IPv6 and host:port.
    parsed = urlsplit(f"//{raw}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in targets are not allowed")
    if parsed.hostname is None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target must be a domain, IP address, or absolute HTTP URL")
    host, kind = _normalize_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target contains an invalid port") from exc
    normalized_host = f"[{host}]" if ":" in host else host
    normalized = f"{normalized_host}:{port}" if port is not None else normalized_host
    return ParsedTarget(
        original=target,
        host=host,
        kind=kind,
        port=port,
        normalized=normalized,
    )


def _matches_scope(host: str, pattern: str) -> bool:
    candidate = pattern.strip().lower().rstrip(".")
    if not candidate:
        return False

    if "/" in candidate:
        try:
            network = ipaddress.ip_network(candidate, strict=False)
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False

    if candidate.startswith("*."):
        try:
            suffix, suffix_kind = _normalize_host(candidate[2:])
        except ValueError:
            return False
        return suffix_kind == "domain" and host != suffix and host.endswith(f".{suffix}")

    try:
        normalized, _ = _normalize_host(candidate)
    except ValueError:
        return False
    return host == normalized


def _is_non_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not address.is_global


class ScopePolicy:
    """Evaluate configured allow/block patterns and resolved network addresses."""

    def __init__(self, config: BugBountyConfig):
        self.config = config

    def evaluate(self, target: str) -> ScopeDecision:
        try:
            parsed = parse_target(target)
        except ValueError as exc:
            return ScopeDecision(False, str(exc))

        if any(_matches_scope(parsed.host, pattern) for pattern in self.config.blocked_targets):
            return ScopeDecision(False, "target matches the blocked-target list", parsed)

        if self.config.safe_mode:
            if not self.config.allowed_targets:
                return ScopeDecision(
                    False,
                    "safe mode is enabled and ALLOWED_TARGETS is empty",
                    parsed,
                )
            if not any(
                _matches_scope(parsed.host, pattern) for pattern in self.config.allowed_targets
            ):
                return ScopeDecision(False, "target is outside ALLOWED_TARGETS", parsed)

        if parsed.kind == "ip":
            address = ipaddress.ip_address(parsed.host)
            if _is_non_public_address(address) and not self.config.allow_private_targets:
                return ScopeDecision(
                    False,
                    "private, loopback, link-local, reserved, and multicast targets are disabled",
                    parsed,
                )

        return ScopeDecision(True, "target is authorized", parsed)

    def require(self, target: str, *, require_url: bool = False) -> ParsedTarget:
        try:
            parsed = parse_target(target, require_url=require_url)
        except ValueError as exc:
            raise ScopeViolation(str(exc)) from exc
        decision = self.evaluate(target)
        if not decision.allowed:
            raise ScopeViolation(decision.reason)
        return parsed

    async def require_network_safe(self, target: str, *, require_url: bool = False) -> ParsedTarget:
        """Authorize a target and reject unexpected non-public DNS answers."""
        parsed, _addresses = await self.resolve_network_safe(target, require_url=require_url)
        return parsed

    async def resolve_network_safe(
        self,
        target: str,
        *,
        require_url: bool = False,
    ) -> tuple[ParsedTarget, tuple[str, ...]]:
        """Authorize and resolve a target, returning the exact validated addresses.

        Network callers should connect to one of the returned numeric addresses and
        retain the original hostname for HTTP Host/TLS SNI. This closes the DNS
        validation-to-connection gap that otherwise permits rebinding.
        """
        parsed = self.require(target, require_url=require_url)
        if parsed.kind == "ip":
            return parsed, (parsed.host,)

        loop = asyncio.get_running_loop()
        try:
            records = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(parsed.host, parsed.port, type=socket.SOCK_STREAM),
            )
        except socket.gaierror as exc:
            raise ScopeViolation(f"DNS resolution failed for {parsed.host}: {exc}") from exc

        addresses = {ipaddress.ip_address(str(record[4][0])).compressed for record in records}
        if not addresses:
            raise ScopeViolation(f"DNS resolution returned no addresses for {parsed.host}")
        non_public = sorted(
            address
            for address in addresses
            if _is_non_public_address(ipaddress.ip_address(address))
        )
        if non_public and not self.config.allow_private_targets:
            raise ScopeViolation(
                f"{parsed.host} resolves to disallowed non-public address(es): "
                + ", ".join(non_public)
            )
        return parsed, tuple(sorted(addresses))
