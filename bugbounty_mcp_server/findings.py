"""Durable, local finding storage and report rendering."""

from __future__ import annotations

import asyncio
import html
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from .utils import atomic_write_json, safe_filename, utc_now

SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {"open", "triaged", "accepted", "resolved", "false_positive"}


class FindingStore:
    """A small JSON-backed finding store with atomic updates."""

    def __init__(self, data_dir: Path, output_dir: Path):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.path = data_dir / "findings.json"
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
    ) -> dict[str, Any]:
        severity = severity.lower()
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
        if not title.strip() or not description.strip() or not target.strip():
            raise ValueError("title, target, and description cannot be empty")
        now = utc_now()
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
            "created_at": now,
            "updated_at": now,
            "history": [{"status": "open", "at": now}],
        }
        async with self._lock:
            findings = self._load_unlocked()
            findings.append(finding)
            atomic_write_json(self.path, findings)
        return finding

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
        if format not in {"json", "markdown", "html"}:
            raise ValueError("format must be json, markdown, or html")
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
        extension = {"json": "json", "markdown": "md", "html": "html"}[format]
        path = self.output_dir / f"report-{target_part}-{timestamp}.{extension}"
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            atomic_write_json(path, report)
        elif format == "markdown":
            path.write_text(self._render_markdown(report), encoding="utf-8")
        else:
            path.write_text(self._render_html(report), encoding="utf-8")
        return {"path": str(path.resolve()), **report}

    @staticmethod
    def _render_markdown(report: dict[str, Any]) -> str:
        target = report.get("target") or "All targets"
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
                    f"## [{finding['severity'].upper()}] {finding['title']}",
                    "",
                    f"- ID: `{finding['id']}`",
                    f"- Target: `{finding['target']}`",
                    f"- Status: {finding['status']}",
                    "",
                    finding["description"],
                ]
            )
            if finding.get("evidence"):
                lines.extend(["", "### Evidence", "", finding["evidence"]])
            if finding.get("remediation"):
                lines.extend(["", "### Remediation", "", finding["remediation"]])
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
                f"<strong>Status:</strong> {html.escape(finding['status'])}</p>"
                f"<p>{html.escape(finding['description'])}</p>"
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
