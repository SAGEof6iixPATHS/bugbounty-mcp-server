from __future__ import annotations

import pytest

from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.scope import ScopePolicy, ScopeViolation, parse_target


def test_safe_mode_fails_closed_without_allowlist() -> None:
    policy = ScopePolicy(BugBountyConfig())

    decision = policy.evaluate("https://example.com/path")

    assert decision.allowed is False
    assert "ALLOWED_TARGETS is empty" in decision.reason


def test_exact_and_wildcard_domains_have_label_boundaries() -> None:
    exact = ScopePolicy(BugBountyConfig(allowed_targets=["example.com"]))
    wildcard = ScopePolicy(BugBountyConfig(allowed_targets=["*.example.com"]))

    assert exact.evaluate("example.com").allowed
    assert not exact.evaluate("api.example.com").allowed
    assert not exact.evaluate("notexample.com").allowed
    assert wildcard.evaluate("api.example.com").allowed
    assert wildcard.evaluate("deep.api.example.com").allowed
    assert not wildcard.evaluate("example.com").allowed
    assert not wildcard.evaluate("example.com.attacker.test").allowed


def test_blocklist_takes_precedence() -> None:
    policy = ScopePolicy(
        BugBountyConfig(
            allowed_targets=["*.example.com"],
            blocked_targets=["admin.example.com"],
        )
    )

    assert policy.evaluate("api.example.com").allowed
    decision = policy.evaluate("admin.example.com")
    assert not decision.allowed
    assert "blocked-target" in decision.reason


def test_cidr_scope_and_private_target_opt_in() -> None:
    denied = ScopePolicy(BugBountyConfig(allowed_targets=["10.0.0.0/8"]))
    allowed = ScopePolicy(
        BugBountyConfig(
            allowed_targets=["10.0.0.0/8"],
            allow_private_targets=True,
        )
    )

    assert not denied.evaluate("10.1.2.3").allowed
    assert allowed.evaluate("10.1.2.3").allowed
    assert not allowed.evaluate("192.168.1.1").allowed


def test_url_parsing_normalizes_case_idna_default_port_and_fragment() -> None:
    parsed = parse_target("HTTPS://BÜCHER.Example:443/a?q=1#fragment", require_url=True)

    assert parsed.host == "xn--bcher-kva.example"
    assert parsed.port == 443
    assert parsed.normalized == "https://xn--bcher-kva.example/a?q=1"


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.com/file",
        "https://user:password@example.com/",
        "https://example.com:99999/",
        "example.com/path",
        "",
    ],
)
def test_invalid_targets_are_rejected(target: str) -> None:
    with pytest.raises(ValueError):
        parse_target(target)


def test_require_raises_a_specific_scope_error() -> None:
    policy = ScopePolicy(BugBountyConfig(allowed_targets=["example.com"]))

    with pytest.raises(ScopeViolation, match="outside ALLOWED_TARGETS"):
        policy.require("attacker.test")


@pytest.mark.asyncio
async def test_network_safety_accepts_public_dns_and_rejects_private_answers(monkeypatch) -> None:
    policy = ScopePolicy(BugBountyConfig(allowed_targets=["example.com"]))

    monkeypatch.setattr(
        "bugbounty_mcp_server.scope.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    parsed = await policy.require_network_safe("https://example.com")
    assert parsed.host == "example.com"
    resolved, addresses = await policy.resolve_network_safe("https://example.com")
    assert resolved.host == "example.com"
    assert addresses == ("93.184.216.34",)

    monkeypatch.setattr(
        "bugbounty_mcp_server.scope.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ScopeViolation, match="non-public"):
        await policy.require_network_safe("https://example.com")


@pytest.mark.asyncio
async def test_network_safety_reports_dns_failure(monkeypatch) -> None:
    import socket

    policy = ScopePolicy(BugBountyConfig(allowed_targets=["example.com"]))

    def fail(*_args, **_kwargs):
        raise socket.gaierror("no answer")

    monkeypatch.setattr("bugbounty_mcp_server.scope.socket.getaddrinfo", fail)

    with pytest.raises(ScopeViolation, match="DNS resolution failed"):
        await policy.require_network_safe("example.com")
