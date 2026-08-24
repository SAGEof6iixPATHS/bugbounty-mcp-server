"""Validated configuration loading for the BugBounty MCP server."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"expected a boolean, got {value!r}")


def _parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _set_nested(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = data
    for key in path[:-1]:
        child = cursor.get(key)
        if not isinstance(child, dict):
            child = {}
            cursor[key] = child
        cursor = child
    cursor[path[-1]] = value


class ToolConfig(BaseModel):
    """Optional external tool integration settings."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    nuclei_path: str = "nuclei"
    enable_nuclei: bool = False


class ScanConfig(BaseModel):
    """Network operation limits. All limits are enforced server-side."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    default_ports: list[int] = Field(
        default_factory=lambda: [
            21,
            22,
            25,
            53,
            80,
            110,
            143,
            443,
            445,
            993,
            995,
            1433,
            3000,
            3306,
            3389,
            5432,
            6379,
            8000,
            8080,
            8443,
            9000,
            9200,
            27017,
        ]
    )
    max_ports_per_scan: int = Field(default=1024, ge=1, le=65535)
    max_concurrency: int = Field(default=30, ge=1, le=200)
    connect_timeout: float = Field(default=2.0, gt=0, le=30)
    request_timeout: float = Field(default=15.0, gt=0, le=120)
    max_response_bytes: int = Field(default=1_000_000, ge=1024, le=10_000_000)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_crawl_depth: int = Field(default=2, ge=0, le=5)
    max_pages_to_crawl: int = Field(default=30, ge=1, le=200)
    max_directory_requests: int = Field(default=100, ge=1, le=1000)
    directory_wordlist: Path | None = None

    @field_validator("default_ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        if not ports:
            raise ValueError("default_ports cannot be empty")
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("ports must be between 1 and 65535")
        return sorted(set(ports))


class OutputConfig(BaseModel):
    """Finding persistence and report output settings."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    output_dir: Path = Path("output")
    data_dir: Path = Path("data")


class BugBountyConfig(BaseModel):
    """Main server configuration.

    Safe mode is fail-closed: when enabled, an empty allow-list authorizes no
    network target. Wildcard domains and CIDR ranges are supported.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    log_level: str = "INFO"
    safe_mode: bool = True
    allowed_targets: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)
    allow_private_targets: bool = False
    requests_per_second: float = Field(default=5.0, gt=0, le=100)
    tool_timeout: float = Field(default=300.0, gt=0, le=3600)
    max_tool_output_chars: int = Field(default=200_000, ge=1000, le=2_000_000)
    user_agent: str = "bugbounty-mcp-server/2.0 (+authorized-security-testing)"
    tools: ToolConfig = Field(default_factory=ToolConfig)
    scanning: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
        return normalized

    @field_validator("allowed_targets", "blocked_targets")
    @classmethod
    def validate_scope_entries(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values if value.strip()]
        if len(cleaned) != len(set(cleaned)):
            cleaned = list(dict.fromkeys(cleaned))
        return cleaned

    @classmethod
    def load(
        cls,
        config_path: str | Path | None = None,
        *,
        env_file: str | Path | None = ".env",
    ) -> BugBountyConfig:
        """Load defaults, then a JSON/YAML file, then environment overrides."""
        if env_file is not None:
            load_dotenv(dotenv_path=env_file, override=False)

        data: dict[str, Any] = {}
        if config_path is not None:
            path = Path(config_path).expanduser()
            if not path.is_file():
                raise ValueError(f"configuration file does not exist: {path}")
            try:
                if path.suffix.lower() == ".json":
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                elif path.suffix.lower() in {".yaml", ".yml"}:
                    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
                else:
                    raise ValueError("configuration file must use .json, .yaml, or .yml")
            except (json.JSONDecodeError, yaml.YAMLError) as exc:
                raise ValueError(f"invalid configuration file: {exc}") from exc
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise ValueError("configuration root must be an object")
            data = deepcopy(loaded)

        env_bindings: dict[str, tuple[tuple[str, ...], Callable[[str], Any]]] = {
            "LOG_LEVEL": (("log_level",), str),
            "SAFE_MODE": (("safe_mode",), _parse_bool),
            "ALLOWED_TARGETS": (("allowed_targets",), _parse_csv),
            "BLOCKED_TARGETS": (("blocked_targets",), _parse_csv),
            "ALLOW_PRIVATE_TARGETS": (("allow_private_targets",), _parse_bool),
            "REQUESTS_PER_SECOND": (("requests_per_second",), float),
            "TOOL_TIMEOUT": (("tool_timeout",), float),
            "MAX_TOOL_OUTPUT_CHARS": (("max_tool_output_chars",), int),
            "USER_AGENT": (("user_agent",), str),
            "OUTPUT_DIR": (("output", "output_dir"), Path),
            "DATA_DIR": (("output", "data_dir"), Path),
            "NUCLEI_PATH": (("tools", "nuclei_path"), str),
            "ENABLE_NUCLEI": (("tools", "enable_nuclei"), _parse_bool),
            "DEFAULT_PORTS": (
                ("scanning", "default_ports"),
                lambda value: [int(port) for port in _parse_csv(value)],
            ),
            "MAX_PORTS_PER_SCAN": (("scanning", "max_ports_per_scan"), int),
            "MAX_CONCURRENT_SCANS": (("scanning", "max_concurrency"), int),
            "DEFAULT_TIMEOUT": (("scanning", "request_timeout"), float),
            "CONNECT_TIMEOUT": (("scanning", "connect_timeout"), float),
            "MAX_RESPONSE_BYTES": (("scanning", "max_response_bytes"), int),
            "MAX_REDIRECTS": (("scanning", "max_redirects"), int),
            "MAX_CRAWL_DEPTH": (("scanning", "max_crawl_depth"), int),
            "MAX_PAGES_TO_CRAWL": (("scanning", "max_pages_to_crawl"), int),
            "MAX_DIRECTORY_REQUESTS": (("scanning", "max_directory_requests"), int),
            "DIRECTORY_WORDLIST": (("scanning", "directory_wordlist"), Path),
        }

        for variable, (field_path, parser) in env_bindings.items():
            raw_value = os.getenv(variable)
            if raw_value is None or raw_value == "":
                continue
            try:
                _set_nested(data, field_path, parser(raw_value))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid {variable}: {exc}") from exc

        return cls.model_validate(data)

    @classmethod
    def from_file(cls, path: str | Path) -> BugBountyConfig:
        """Compatibility alias for older callers."""
        return cls.load(path)

    def ensure_directories(self) -> None:
        """Create runtime-owned storage directories."""
        self.output.output_dir.mkdir(parents=True, exist_ok=True)
        self.output.data_dir.mkdir(parents=True, exist_ok=True)

    def is_target_allowed(self, target: str) -> bool:
        """Return target scope status without raising or performing DNS."""
        from .scope import ScopePolicy

        return ScopePolicy(self).evaluate(target).allowed
