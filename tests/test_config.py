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
