"""Durable, local finding storage and report rendering."""

from __future__ import annotations

import asyncio
import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from .utils import (
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    safe_filename,
    stable_hash,
    utc_now,
)

SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {"open", "triaged", "accepted", "resolved", "false_positive"}
CONFIDENCES = {"confirmed", "firm", "tentative"}


def _markdown_escape(value: Any, *, inline: bool = False) -> str:
    escaped = html.escape(str(value), quote=False).replace("`", "&#96;")
    return " ".join(escaped.splitlines()) if inline else escaped


class FindingStore:
    """A small JSON-backed finding store with atomic updates."""

    def __init__(self, data_dir: Path, output_dir: Path, *, max_evidence_bytes: int = 500_000):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.path = data_dir / "findings.json"
        self.evidence_dir = data_dir / "evidence"
        self.max_evidence_bytes = max_evidence_bytes
        self._lock = asyncio.Lock()

    def _load_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"finding store is unreadable: {exc}") from exc
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError("finding store must contain a JSON array of objects")
        return value

    async def create(
        self,
        *,
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
        severity = severity.lower()
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
        if not title.strip() or not description.strip() or not target.strip():
            raise ValueError("title, target, and description cannot be empty")
        confidence = confidence.lower()
        if confidence not in CONFIDENCES:
            raise ValueError(f"confidence must be one of: {', '.join(sorted(CONFIDENCES))}")
        if cvss_score is not None and not 0 <= cvss_score <= 10:
            raise ValueError("cvss_score must be between 0 and 10")
        normalized_cwe = cwe.upper().strip() if cwe else None
        if normalized_cwe and not (
            normalized_cwe == "NVD-CWE-OTHER"
            or normalized_cwe == "NVD-CWE-NOINFO"
            or (normalized_cwe.startswith("CWE-") and normalized_cwe[4:].isdigit())
        ):
            raise ValueError("cwe must look like CWE-79, NVD-CWE-OTHER, or NVD-CWE-NOINFO")
        now = utc_now()
        fingerprint = stable_hash(
            "\x00".join([target.strip().casefold(), title.strip().casefold(), normalized_cwe or ""])
        )
        finding: dict[str, Any] = {
            "id": str(uuid4()),
            "title": title.strip(),
            "severity": severity,
            "status": "open",
            "target": target.strip(),
            "description": description.strip(),
            "evidence": evidence.strip() if evidence else None,
            "remediation": remediation.strip() if remediation else None,
            "references": references or [],
            "impact": impact.strip() if impact else None,
            "steps_to_reproduce": [
                step.strip() for step in steps_to_reproduce or [] if step.strip()
            ],
            "cwe": normalized_cwe,
            "cvss_score": cvss_score,
            "confidence": confidence,
            "tags": sorted({tag.strip().lower() for tag in tags or [] if tag.strip()}),
            "source_tool": source_tool.strip() if source_tool else None,
            "fingerprint": fingerprint,
            "evidence_artifacts": [],
            "created_at": now,
            "updated_at": now,
            "history": [{"status": "open", "at": now}],
        }
        async with self._lock:
            findings = self._load_unlocked()
            findings.append(finding)
            atomic_write_json(self.path, findings)
        return finding

    async def get(self, finding_id: str) -> dict[str, Any]:
        """Return one finding by identifier."""
        async with self._lock:
            findings = self._load_unlocked()
        for finding in findings:
            if finding.get("id") == finding_id:
                return finding
        raise ValueError(f"finding not found: {finding_id}")

    async def summary(self) -> dict[str, Any]:
        findings = await self.list()
        return {
            "total": len(findings),
            "by_severity": {
                severity: sum(item.get("severity") == severity for item in findings)
                for severity in ["critical", "high", "medium", "low", "info"]
            },
            "by_status": {
                status: sum(item.get("status") == status for item in findings)
                for status in sorted(STATUSES)
            },
            "targets": sorted({str(item.get("target")) for item in findings if item.get("target")}),
        }

    async def add_evidence(
        self,
        finding_id: str,
        *,
        label: str,
        content: str,
        media_type: str = "text/plain",
    ) -> dict[str, Any]:
        """Attach a private, content-addressed evidence artifact to a finding."""
        payload = content.encode("utf-8")
        if not label.strip():
            raise ValueError("evidence label cannot be empty")
        if not payload:
            raise ValueError("evidence content cannot be empty")
        if len(payload) > self.max_evidence_bytes:
            raise ValueError(
                f"evidence exceeds the configured {self.max_evidence_bytes}-byte limit"
            )
        if not media_type.startswith("text/") and media_type not in {
            "application/json",
            "application/xml",
        }:
            raise ValueError(
                "evidence media_type must be text, application/json, or application/xml"
            )

        evidence_id = str(uuid4())
        digest = stable_hash(payload)
        extension = {
            "application/json": "json",
            "application/xml": "xml",
        }.get(media_type, "txt")
        relative_path = Path("evidence") / finding_id / f"{evidence_id}.{extension}"
        destination = self.data_dir / relative_path
        now = utc_now()
        artifact = {
            "id": evidence_id,
            "label": label.strip(),
            "media_type": media_type,
            "size": len(payload),
            "sha256": digest,
            "created_at": now,
            "resource_uri": f"bugbounty://evidence/{evidence_id}",
            "path": str(relative_path),
        }
        async with self._lock:
            findings = self._load_unlocked()
            for finding in findings:
                if finding.get("id") != finding_id:
                    continue
                atomic_write_bytes(destination, payload)
                finding.setdefault("evidence_artifacts", []).append(artifact)
                finding["updated_at"] = now
                atomic_write_json(self.path, findings)
                return artifact
        raise ValueError(f"finding not found: {finding_id}")

    async def read_evidence(self, evidence_id: str) -> tuple[dict[str, Any], str]:
        """Read one indexed evidence artifact after verifying its digest."""
        async with self._lock:
            findings = self._load_unlocked()
            for finding in findings:
                for artifact in finding.get("evidence_artifacts", []):
                    if artifact.get("id") != evidence_id:
                        continue
                    path = (self.data_dir / str(artifact["path"])).resolve()
                    evidence_root = self.evidence_dir.resolve()
                    if not path.is_relative_to(evidence_root):
                        raise ValueError("evidence artifact path is outside the evidence directory")
                    try:
                        payload = path.read_bytes()
                    except OSError as exc:
                        raise ValueError(f"evidence artifact is unreadable: {exc}") from exc
                    if stable_hash(payload) != artifact.get("sha256"):
                        raise ValueError("evidence artifact integrity check failed")
                    return artifact, payload.decode("utf-8", errors="replace")
        raise ValueError(f"evidence not found: {evidence_id}")

    async def list(
        self,
        *,
        target: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        if severity is not None and severity.lower() not in SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
        if status is not None and status.lower() not in STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(STATUSES))}")
        async with self._lock:
            findings = self._load_unlocked()
        return [
            finding
            for finding in findings
            if (target is None or finding.get("target") == target)
            and (severity is None or finding.get("severity") == severity.lower())
            and (status is None or finding.get("status") == status.lower())
        ]

    async def update(
        self,
        finding_id: str,
        *,
        status: str,
        remediation: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        status = status.lower()
        if status not in STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(STATUSES))}")
        async with self._lock:
            findings = self._load_unlocked()
            for finding in findings:
                if finding.get("id") != finding_id:
                    continue
                now = utc_now()
                finding["status"] = status
                finding["updated_at"] = now
                if remediation is not None:
                    finding["remediation"] = remediation.strip() or None
                event: dict[str, Any] = {"status": status, "at": now}
                if note:
                    event["note"] = note.strip()
                finding.setdefault("history", []).append(event)
                atomic_write_json(self.path, findings)
                return finding
        raise ValueError(f"finding not found: {finding_id}")

    async def report(self, *, format: str, target: str | None = None) -> dict[str, Any]:
        format = format.lower()
        if format not in {"json", "markdown", "html", "sarif"}:
            raise ValueError("format must be json, markdown, html, or sarif")
        findings = await self.list(target=target)
        generated_at = utc_now()
        summary = {
            severity: sum(finding.get("severity") == severity for finding in findings)
            for severity in ["critical", "high", "medium", "low", "info"]
        }
        report = {
            "generated_at": generated_at,
            "target": target,
            "total_findings": len(findings),
            "by_severity": summary,
            "findings": findings,
        }
        timestamp = generated_at.replace(":", "-").replace("+", "_")
        target_part = safe_filename(target or "all-targets")
        extension = {"json": "json", "markdown": "md", "html": "html", "sarif": "sarif"}[format]
        path = self.output_dir / f"report-{target_part}-{timestamp}.{extension}"
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            atomic_write_json(path, report)
        elif format == "markdown":
            atomic_write_text(path, self._render_markdown(report))
        elif format == "html":
            atomic_write_text(path, self._render_html(report))
        else:
            atomic_write_json(path, self._render_sarif(report))
        return {"path": str(path.resolve()), **report}

    @staticmethod
    def _render_sarif(report: dict[str, Any]) -> dict[str, Any]:
        """Render interoperable SARIF 2.1.0 without embedding evidence bodies."""
        level_by_severity = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        results = []
        rules: dict[str, dict[str, Any]] = {}
        for finding in report["findings"]:
            rule_id = finding.get("cwe") or "BUGBOUNTY-MCP-FINDING"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": safe_filename(finding["title"], fallback="finding"),
                    "shortDescription": {"text": finding["title"]},
                    "help": {"text": finding.get("remediation") or "Review and remediate."},
                    "properties": {"tags": finding.get("tags") or []},
                },
            )
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level_by_severity.get(finding.get("severity"), "warning"),
                "message": {"text": finding["description"]},
                "fingerprints": {"bugbountyMcp/v1": finding.get("fingerprint", finding["id"])},
                "properties": {
                    "findingId": finding["id"],
                    "severity": finding["severity"],
                    "status": finding["status"],
                    "confidence": finding.get("confidence"),
                    "cvssScore": finding.get("cvss_score"),
                    "target": finding.get("target"),
                },
            }
            target = finding.get("target")
            if isinstance(target, str) and urlsplit(target).scheme in {"http", "https"}:
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": target}}}]
            results.append(result)
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bugbounty-mcp-server",
                            "informationUri": ("https://github.com/gokulapap/bugbounty-mcp-server"),
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "properties": {"generatedAt": report["generated_at"]},
                }
            ],
        }

    @staticmethod
    def _render_markdown(report: dict[str, Any]) -> str:
        target = _markdown_escape(report.get("target") or "All targets", inline=True)
        lines = [
            "# Security Assessment Report",
            "",
            f"Target: {target}",
            f"Generated: {report['generated_at']}",
            f"Total findings: {report['total_findings']}",
            "",
            "## Severity summary",
            "",
        ]
        for severity, count in report["by_severity"].items():
            lines.append(f"- {severity.title()}: {count}")
        for finding in report["findings"]:
            lines.extend(
                [
                    "",
                    f"## [{finding['severity'].upper()}] "
                    f"{_markdown_escape(finding['title'], inline=True)}",
                    "",
                    f"- ID: `{finding['id']}`",
                    f"- Target: `{_markdown_escape(finding['target'], inline=True)}`",
                    f"- Status: {_markdown_escape(finding['status'], inline=True)}",
                    f"- Confidence: "
                    f"{_markdown_escape(finding.get('confidence', 'firm'), inline=True)}",
                    "",
                    _markdown_escape(finding["description"]),
                ]
            )
            if finding.get("cwe"):
                lines.insert(-2, f"- CWE: {finding['cwe']}")
            if finding.get("cvss_score") is not None:
                lines.insert(-2, f"- CVSS score: {finding['cvss_score']}")
            if finding.get("impact"):
                lines.extend(["", "### Impact", "", _markdown_escape(finding["impact"])])
            if finding.get("steps_to_reproduce"):
                lines.extend(["", "### Steps to reproduce", ""])
                lines.extend(
                    f"{index}. {_markdown_escape(step)}"
                    for index, step in enumerate(finding["steps_to_reproduce"], start=1)
                )
            if finding.get("evidence"):
                lines.extend(["", "### Evidence", "", _markdown_escape(finding["evidence"])])
            if finding.get("evidence_artifacts"):
                lines.extend(["", "### Evidence artifacts", ""])
                lines.extend(
                    f"- {_markdown_escape(artifact['label'], inline=True)} — "
                    f"`{artifact['sha256']}` ({artifact['size']} bytes)"
                    for artifact in finding["evidence_artifacts"]
                )
            if finding.get("remediation"):
                lines.extend(["", "### Remediation", "", _markdown_escape(finding["remediation"])])
            if finding.get("references"):
                lines.extend(["", "### References", ""])
                lines.extend(
                    f"- {_markdown_escape(reference, inline=True)}"
                    for reference in finding["references"]
                )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_html(report: dict[str, Any]) -> str:
        items = []
        for finding in report["findings"]:
            items.append(
                "<article>"
                f"<h2><span class='severity {html.escape(finding['severity'])}'>"
                f"{html.escape(finding['severity'].upper())}</span> "
                f"{html.escape(finding['title'])}</h2>"
                f"<p><strong>Target:</strong> {html.escape(finding['target'])} &middot; "
                f"<strong>Status:</strong> {html.escape(finding['status'])} &middot; "
                f"<strong>Confidence:</strong> "
                f"{html.escape(finding.get('confidence', 'firm'))}</p>"
                f"<p>{html.escape(finding['description'])}</p>"
                + (
                    f"<h3>Impact</h3><p>{html.escape(finding['impact'])}</p>"
                    if finding.get("impact")
                    else ""
                )
                + (
                    "<h3>Steps to reproduce</h3><ol>"
                    + "".join(
                        f"<li>{html.escape(step)}</li>"
                        for step in finding.get("steps_to_reproduce", [])
                    )
                    + "</ol>"
                    if finding.get("steps_to_reproduce")
                    else ""
                )
                + (
                    f"<h3>Evidence</h3><pre>{html.escape(finding['evidence'])}</pre>"
                    if finding.get("evidence")
                    else ""
                )
                + (
                    f"<h3>Remediation</h3><p>{html.escape(finding['remediation'])}</p>"
                    if finding.get("remediation")
                    else ""
                )
                + "</article>"
            )
        target = html.escape(report.get("target") or "All targets")
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Security Assessment Report</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:40px auto;
padding:0 20px;color:#17202a}}
article{{border-top:1px solid #ddd;padding:20px 0}}
pre{{white-space:pre-wrap;background:#f5f5f5;padding:12px}}
.severity{{font-size:.7em;padding:3px 7px;border-radius:4px;background:#555;color:white}}
.critical{{background:#7b001c}}.high{{background:#c0392b}}.medium{{background:#d68910}}.low{{background:#2471a3}}
</style></head><body><h1>Security Assessment Report</h1>
<p><strong>Target:</strong> {target}<br>
<strong>Generated:</strong> {html.escape(report["generated_at"])}<br>
<strong>Total findings:</strong> {report["total_findings"]}</p>{"".join(items)}</body></html>"""
