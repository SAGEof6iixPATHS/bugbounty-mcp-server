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
    sarif_report = await store.report(format="sarif")

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
    assert "<script>alert(1)</script>" not in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    sarif_text = await asyncio.to_thread(
        Path(sarif_report["path"]).read_text,
        encoding="utf-8",
    )
    sarif = json.loads(sarif_text)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


@pytest.mark.asyncio
async def test_structured_finding_evidence_and_integrity(tmp_path) -> None:
    store = FindingStore(tmp_path / "data", tmp_path / "output", max_evidence_bytes=100)
    finding = await store.create(
        title="Broken object authorization",
        severity="high",
        target="https://example.com/users/2",
        description="Another account is readable.",
        impact="Account data disclosure.",
        steps_to_reproduce=["Sign in", "Request user 2"],
        cwe="CWE-639",
        cvss_score=8.1,
        confidence="confirmed",
        tags=["API", "authorization"],
        source_tool="manual-validation",
    )
    artifact = await store.add_evidence(
        finding["id"],
        label="redacted response",
        content='{"owner":"other"}',
        media_type="application/json",
    )

    metadata, content = await store.read_evidence(artifact["id"])
    loaded = await store.get(finding["id"])
    summary = await store.summary()

    assert content == '{"owner":"other"}'
    assert metadata["sha256"] == loaded["evidence_artifacts"][0]["sha256"]
    assert loaded["fingerprint"]
    assert loaded["tags"] == ["api", "authorization"]
    assert summary["by_severity"]["high"] == 1
    assert (tmp_path / "data" / metadata["path"]).stat().st_mode & 0o777 == 0o600

    (tmp_path / "data" / metadata["path"]).write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        await store.read_evidence(artifact["id"])

    with pytest.raises(ValueError, match="byte limit"):
        await store.add_evidence(finding["id"], label="large", content="x" * 101)


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


@pytest.mark.asyncio
async def test_evidence_index_cannot_escape_evidence_directory(tmp_path) -> None:
    store = FindingStore(tmp_path / "data", tmp_path / "output")
    finding = await store.create(
        title="test",
        severity="info",
        target="example.com",
        description="test",
    )
    artifact = await store.add_evidence(finding["id"], label="test", content="safe")
    records = json.loads(store.path.read_text(encoding="utf-8"))
    records[0]["evidence_artifacts"][0]["path"] = "../outside.txt"
    store.path.write_text(json.dumps(records), encoding="utf-8")

    with pytest.raises(ValueError, match="outside the evidence directory"):
        await store.read_evidence(artifact["id"])
