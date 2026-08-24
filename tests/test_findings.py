from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from bugbounty_mcp_server.findings import FindingStore


@pytest.mark.asyncio
async def test_finding_lifecycle_and_reports_escape_untrusted_html(tmp_path) -> None:
    store = FindingStore(tmp_path / "data", tmp_path / "output")

    created = await store.create(
        title="Reflected <script>alert(1)</script>",
        severity="high",
        target="https://app.example.com",
        description="A reflected parameter executes markup.",
        evidence="<img src=x onerror=alert(1)>",
        remediation="Contextually encode output.",
        references=["https://owasp.org/"],
    )
    updated = await store.update(created["id"], status="triaged", note="Confirmed twice")
    listed = await store.list(severity="high", status="triaged")

    assert updated["status"] == "triaged"
    assert updated["history"][-1]["note"] == "Confirmed twice"
    assert listed == [updated]

    json_report = await store.report(format="json", target="https://app.example.com")
    html_report = await store.report(format="html", target="https://app.example.com")
    markdown_report = await store.report(format="markdown")

    assert json.loads((tmp_path / "data" / "findings.json").read_text())[0]["id"] == created["id"]
    json_text = await asyncio.to_thread(
        Path(json_report["path"]).read_text,
        encoding="utf-8",
    )
    assert json.loads(json_text)["total_findings"] == 1
    html = await asyncio.to_thread(Path(html_report["path"]).read_text, encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    markdown = await asyncio.to_thread(
        Path(markdown_report["path"]).read_text,
        encoding="utf-8",
    )
    assert markdown.startswith("# Security Assessment Report")


@pytest.mark.asyncio
async def test_finding_validation_and_missing_update(tmp_path) -> None:
    store = FindingStore(tmp_path / "data", tmp_path / "output")

    with pytest.raises(ValueError, match="severity"):
        await store.create(title="x", severity="urgent", target="t", description="d")
    with pytest.raises(ValueError, match="cannot be empty"):
        await store.create(title="", severity="low", target="t", description="d")
    with pytest.raises(ValueError, match="finding not found"):
        await store.update("missing", status="resolved")
    with pytest.raises(ValueError, match="format"):
        await store.report(format="pdf")


@pytest.mark.asyncio
async def test_corrupt_store_is_reported(tmp_path) -> None:
    store = FindingStore(tmp_path / "data", tmp_path / "output")
    store.path.parent.mkdir(parents=True)
    store.path.write_text("not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="unreadable"):
        await store.list()
