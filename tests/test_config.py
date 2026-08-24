from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from bugbounty_mcp_server.config import BugBountyConfig


def test_loads_yaml_then_applies_environment_overrides(tmp_path, monkeypatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "safe_mode: false\nallowed_targets: [file.example]\nscanning:\n  max_concurrency: 4\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SAFE_MODE", "true")
    monkeypatch.setenv("ALLOWED_TARGETS", "example.com,*.example.com")
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "12")

    config = BugBountyConfig.load(path, env_file=None)

    assert config.safe_mode is True
    assert config.allowed_targets == ["example.com", "*.example.com"]
    assert config.scanning.max_concurrency == 12


def test_loads_json_and_paths(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"output": {"data_dir": "state", "output_dir": "reports"}}),
        encoding="utf-8",
    )

    config = BugBountyConfig.load(path, env_file=None)

    assert str(config.output.data_dir) == "state"
    assert str(config.output.output_dir) == "reports"


def test_invalid_file_and_environment_values_are_explained(tmp_path, monkeypatch) -> None:
    malformed = tmp_path / "config.yaml"
    malformed.write_text("- not-an-object\n", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be an object"):
        BugBountyConfig.load(malformed, env_file=None)

    monkeypatch.setenv("SAFE_MODE", "sometimes")
    with pytest.raises(ValueError, match="invalid SAFE_MODE"):
        BugBountyConfig.load(env_file=None)


def test_validation_rejects_unknown_keys_and_invalid_limits() -> None:
    with pytest.raises(ValidationError):
        BugBountyConfig.model_validate({"unknown": True})
    with pytest.raises(ValidationError):
        BugBountyConfig.model_validate({"scanning": {"max_concurrency": 0}})
    with pytest.raises(ValidationError):
        BugBountyConfig.model_validate({"scanning": {"default_ports": [0, 80]}})


def test_directory_creation_is_explicit(tmp_path) -> None:
    config = BugBountyConfig(
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"}
    )
    assert not config.output.data_dir.exists()

    config.ensure_directories()

    assert config.output.data_dir.is_dir()
    assert config.output.output_dir.is_dir()


def test_http_token_is_validated_and_never_serialized_in_plaintext(monkeypatch) -> None:
    monkeypatch.setenv("HTTP_BEARER_TOKEN", "a-secure-token-with-24-chars")
    config = BugBountyConfig.load(env_file=None)

    assert config.http.bearer_token is not None
    assert config.http.bearer_token.get_secret_value() == "a-secure-token-with-24-chars"
    assert "a-secure-token" not in config.model_dump_json()

    with pytest.raises(ValidationError, match="at least 24"):
        BugBountyConfig(http={"bearer_token": "too-short"})
    with pytest.raises(ValidationError, match="without whitespace"):
        BugBountyConfig(http={"bearer_token": "a" * 24 + "\n"})


def test_external_tool_configuration_is_explicit_and_validated(monkeypatch) -> None:
    monkeypatch.setenv("ENABLED_EXTERNAL_TOOLS", "gau,subfinder,gau")
    monkeypatch.setenv("SUBFINDER_PATH", "/opt/tools/subfinder")

    config = BugBountyConfig.load(env_file=None)

    assert config.tools.enabled_external_tools == ["gau", "subfinder"]
    assert config.tools.subfinder_path == "/opt/tools/subfinder"

    with pytest.raises(ValidationError, match="unsupported external tools"):
        BugBountyConfig(tools={"enabled_external_tools": ["sqlmap"]})
    with pytest.raises(ValidationError, match="single-line"):
        BugBountyConfig(tools={"gau_path": "gau\n--dangerous"})
