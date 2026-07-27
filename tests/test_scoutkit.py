"""Tests for the shared scoutkit library and the report contract every skill honours."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scoutkit import Finding, Report, Severity, chain_digest, read_jsonl, write_json
from scoutkit.cli import EXIT_BLOCK, EXIT_PASS, EXIT_REVIEW, resolve_exit_code
from scoutkit.hashing import GENESIS, canonical_json
from scoutkit.io import EvidenceError, append_jsonl, read_json, write_text
from scoutkit.render import render_html, render_markdown

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SLUG = "injection-shield"


def make_report(*severities: str) -> Report:
    report = Report(skill="unit-test", subject="fixture", generated_at="2026-01-01T00:00:00Z")
    for index, severity in enumerate(severities, start=1):
        report.add(Finding(code=f"T{index:03d}", severity=severity,
                           title=f"finding {index}", detail="detail", locator="loc"))
    return report


class TestSeverity:
    def test_order_is_descending(self):
        ranks = [Severity.rank(s) for s in Severity.ORDER]
        assert ranks == sorted(ranks)

    def test_max_picks_worst(self):
        assert Severity.max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) == Severity.CRITICAL

    def test_max_of_empty_is_none(self):
        assert Severity.max([]) is None

    def test_validate_rejects_unknown(self):
        with pytest.raises(ValueError):
            Severity.validate("catastrophic")


class TestFinding:
    def test_rejects_unknown_severity(self):
        with pytest.raises(ValueError):
            Finding(code="X", severity="nope", title="t", detail="d")

    def test_rejects_empty_code(self):
        with pytest.raises(ValueError):
            Finding(code="", severity=Severity.LOW, title="t", detail="d")

    def test_is_immutable(self):
        finding = Finding(code="X", severity=Severity.LOW, title="t", detail="d")
        with pytest.raises(AttributeError):
            finding.severity = Severity.HIGH  # type: ignore[misc]


class TestReport:
    def test_findings_sort_worst_first(self):
        report = make_report(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM)
        assert [f.severity for f in report.sorted_findings()] == [
            Severity.CRITICAL, Severity.MEDIUM, Severity.LOW
        ]

    def test_counts_cover_every_level(self):
        counts = make_report(Severity.HIGH, Severity.HIGH).counts()
        assert set(counts) == set(Severity.ORDER)
        assert counts[Severity.HIGH] == 2

    @pytest.mark.parametrize(
        ("severities", "expected"),
        [
            ((), "pass"),
            ((Severity.INFO,), "pass"),
            ((Severity.LOW,), "pass"),
            ((Severity.MEDIUM,), "review"),
            ((Severity.HIGH,), "review"),
            ((Severity.CRITICAL,), "block"),
            ((Severity.LOW, Severity.CRITICAL), "block"),
        ],
    )
    def test_verdict_tracks_worst_finding(self, severities, expected):
        assert make_report(*severities).decide_verdict() == expected

    def test_notes_are_deduplicated(self):
        report = make_report()
        report.note("same")
        report.note("same")
        assert report.notes == ["same"]

    def test_serialization_matches_pack_schema_shape(self):
        payload = make_report(Severity.HIGH).to_dict()
        schema = read_json(ROOT / "references" / "report-schema.json")
        assert set(schema["required"]) <= set(payload)
        assert set(payload) <= set(schema["properties"]), "report emitted an undeclared top-level key"


class TestExitCodes:
    @pytest.mark.parametrize(
        ("verdict", "fail_on", "expected"),
        [
            ("block", "never", EXIT_PASS),
            ("review", "never", EXIT_PASS),
            ("pass", "review", EXIT_PASS),
            ("review", "review", EXIT_REVIEW),
            ("block", "review", EXIT_BLOCK),
            ("review", "block", EXIT_PASS),
            ("block", "block", EXIT_BLOCK),
        ],
    )
    def test_gating_policy(self, verdict, fail_on, expected):
        assert resolve_exit_code(verdict, fail_on) == expected


class TestHashing:
    def test_chain_is_order_sensitive(self):
        first = chain_digest(GENESIS, {"a": 1})
        assert chain_digest(first, {"b": 2}) != chain_digest(GENESIS, {"b": 2})

    def test_chain_is_deterministic(self):
        assert chain_digest(GENESIS, {"b": 2, "a": 1}) == chain_digest(GENESIS, {"a": 1, "b": 2})

    def test_canonical_json_is_key_order_independent(self):
        assert canonical_json({"z": 1, "a": 2}) == canonical_json({"a": 2, "z": 1})

    def test_any_content_change_breaks_the_digest(self):
        assert chain_digest(GENESIS, {"status": "failure"}) != chain_digest(GENESIS, {"status": "success"})


class TestIO:
    def test_write_json_is_byte_reproducible(self, tmp_path: Path):
        payload = {"b": [3, 1, 2], "a": "x"}
        first = write_json(tmp_path / "a.json", payload).read_bytes()
        second = write_json(tmp_path / "b.json", dict(reversed(list(payload.items())))).read_bytes()
        assert first == second

    def test_write_text_creates_parents(self, tmp_path: Path):
        target = write_text(tmp_path / "deep" / "nested" / "f.txt", "hello")
        assert target.read_text(encoding="utf-8") == "hello"

    def test_read_json_reports_bad_json_as_evidence_error(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(EvidenceError):
            read_json(bad)

    def test_read_jsonl_of_missing_file_is_empty(self, tmp_path: Path):
        assert read_jsonl(tmp_path / "absent.jsonl") == []

    def test_append_jsonl_round_trips(self, tmp_path: Path):
        path = tmp_path / "l.jsonl"
        append_jsonl(path, {"n": 1})
        append_jsonl(path, {"n": 2})
        assert [r["n"] for r in read_jsonl(path)] == [1, 2]


class TestRender:
    def test_markdown_escapes_pipes_so_tables_survive(self):
        report = Report(skill="s", generated_at="t")
        report.add(Finding(code="C", severity=Severity.LOW, title="a | b", detail="c | d"))
        body = render_markdown(report, title="T")
        assert "a \\| b" in body

    def test_html_is_self_contained_and_scriptless(self):
        html = render_html(make_report(Severity.HIGH), title="T")
        assert "<script" not in html.lower()
        assert "http://" not in html and "https://" not in html
        assert "<style>" in html

    def test_html_escapes_injected_markup(self):
        report = Report(skill="s", generated_at="t")
        report.add(Finding(code="C", severity=Severity.LOW, title="<img src=x onerror=alert(1)>", detail="d"))
        html = render_html(report, title="T")
        assert "<img src=x" not in html
        assert "&lt;img" in html

    def test_empty_report_renders_both_formats(self):
        report = make_report()
        report.decide_verdict()
        assert "No findings" in render_markdown(report, title="T")
        assert "No findings" in render_html(report, title="T")


def test_skill_manifest_is_wellformed():
    """This standalone repo declares an engine, a template, and a test file that exist."""
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["name"] == ROOT.name or manifest["name"] == MANIFEST_SLUG
    assert manifest["network_required"] is False
    assert manifest["cloud_writes"] is False
    assert manifest["sends_messages"] is False
    for key in ("engine", "template", "tests"):
        assert (ROOT / manifest[key]).is_file(), f"missing {key} -> {manifest[key]}"
    for name in ("SKILL.md", "skill.yaml", "README.md", "setup.md"):
        assert (ROOT / name).is_file(), f"missing {name}"
    assert (ROOT / manifest["schemas"]["output"]).is_file(), "vendored schema is missing"


def test_catalog_preview_assets_exist():
    """The catalog card image and its editable source both ship with the repo."""
    for asset in ("screenshots/preview.png", "screenshots/preview.svg"):
        path = ROOT / asset
        assert path.is_file(), f"missing catalog asset: {asset}"
        assert path.stat().st_size > 0, f"empty catalog asset: {asset}"


def test_vendored_library_is_complete():
    """Every scoutkit module the engines rely on is present in this repo."""
    lib = ROOT / "lib" / "scoutkit"
    for module in ("__init__.py", "cli.py", "findings.py", "hashing.py", "io.py", "render.py"):
        assert (lib / module).is_file(), f"vendored scoutkit is missing {module}"
