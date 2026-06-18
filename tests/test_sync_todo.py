"""Unit tests for scripts/sync-todo.py.

Tests cover:
  - title_of() markdown title extraction
  - detection_files() discovery
  - list_markdown() / cves() / playbooks() / workflows() helpers
  - render_detections() table rendering
  - render_simple_list() list rendering
  - render_summary() summary table
  - tactic_counts() mapping
  - replace_blocks() marker replacement
  - main() with --check flag
"""
from __future__ import annotations

import sys
import textwrap
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import importlib

# We need to reload to pick up the path
if "sync-todo" in sys.modules:
    del sys.modules["sync-todo"]

# Import with hyphenated name via importlib
spec = importlib.util.spec_from_file_location(
    "sync_todo",
    str(Path(__file__).resolve().parent.parent / "scripts" / "sync-todo.py"),
)
sync_todo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_todo)


# ---------------------------------------------------------------------------
# Tests: title_of()
# ---------------------------------------------------------------------------

class TestTitleOf:
    def test_extracts_h1_title(self, tmp_path: Path):
        f = tmp_path / "doc.md"
        f.write_text("# My Great Title\n\nSome content.\n", encoding="utf-8")
        assert sync_todo.title_of(f) == "My Great Title"

    def test_returns_stem_when_no_heading(self, tmp_path: Path):
        f = tmp_path / "no-heading.md"
        f.write_text("Just some text without a heading.\n", encoding="utf-8")
        assert sync_todo.title_of(f) == "no-heading"

    def test_returns_stem_on_read_error(self, tmp_path: Path):
        f = tmp_path / "missing.md"
        # File doesn't exist
        assert sync_todo.title_of(f) == "missing"

    def test_strips_whitespace(self, tmp_path: Path):
        f = tmp_path / "spaced.md"
        f.write_text("#   Spaced Title   \n", encoding="utf-8")
        assert sync_todo.title_of(f) == "Spaced Title"


# ---------------------------------------------------------------------------
# Tests: detection_files()
# ---------------------------------------------------------------------------

class TestDetectionFiles:
    def test_finds_kql_and_sigma(self, tmp_path: Path):
        kql_dir = tmp_path / "detections" / "kql"
        kql_dir.mkdir(parents=True)
        sigma_dir = tmp_path / "detections" / "sigma"
        sigma_dir.mkdir(parents=True)

        (kql_dir / "T1059.001_powershell-encoded.md").write_text(
            "# PowerShell Encoded Command\n", encoding="utf-8"
        )
        (sigma_dir / "T1059.001_powershell-encoded.md").write_text(
            "# PowerShell Encoded Command\n", encoding="utf-8"
        )

        with patch.object(sync_todo, "REPO", tmp_path):
            result = sync_todo.detection_files()

        assert "T1059.001" in result
        assert "kql" in result["T1059.001"]["backends"]
        assert "sigma" in result["T1059.001"]["backends"]

    def test_skips_template_files(self, tmp_path: Path):
        kql_dir = tmp_path / "detections" / "kql"
        kql_dir.mkdir(parents=True)

        (kql_dir / "_template.md").write_text("# Template\n", encoding="utf-8")
        (kql_dir / "T1059.001_real.md").write_text("# Real\n", encoding="utf-8")

        with patch.object(sync_todo, "REPO", tmp_path):
            result = sync_todo.detection_files()

        assert "T1059.001" in result
        # Template should not appear
        assert all("template" not in v["title"].lower() for v in result.values())

    def test_empty_when_no_dir(self, tmp_path: Path):
        with patch.object(sync_todo, "REPO", tmp_path):
            result = sync_todo.detection_files()
        assert result == {}


# ---------------------------------------------------------------------------
# Tests: list_markdown()
# ---------------------------------------------------------------------------

class TestListMarkdown:
    def test_returns_sorted_md_files(self, tmp_path: Path):
        (tmp_path / "b.md").write_text("B", encoding="utf-8")
        (tmp_path / "a.md").write_text("A", encoding="utf-8")
        (tmp_path / "c.txt").write_text("C", encoding="utf-8")

        result = sync_todo.list_markdown(tmp_path)
        assert [p.name for p in result] == ["a.md", "b.md"]

    def test_skips_readme(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Readme", encoding="utf-8")
        (tmp_path / "guide.md").write_text("# Guide", encoding="utf-8")

        result = sync_todo.list_markdown(tmp_path)
        assert [p.name for p in result] == ["guide.md"]

    def test_skips_underscore_prefix(self, tmp_path: Path):
        (tmp_path / "_template.md").write_text("# Template", encoding="utf-8")
        (tmp_path / "real.md").write_text("# Real", encoding="utf-8")

        result = sync_todo.list_markdown(tmp_path)
        assert [p.name for p in result] == ["real.md"]

    def test_empty_for_nonexistent_dir(self, tmp_path: Path):
        result = sync_todo.list_markdown(tmp_path / "nonexistent")
        assert result == []

    def test_predicate_filter(self, tmp_path: Path):
        (tmp_path / "CVE-2024-1234.md").write_text("CVE", encoding="utf-8")
        (tmp_path / "other.md").write_text("Other", encoding="utf-8")

        result = sync_todo.list_markdown(
            tmp_path, predicate=lambda p: p.name.startswith("CVE-")
        )
        assert [p.name for p in result] == ["CVE-2024-1234.md"]


# ---------------------------------------------------------------------------
# Tests: render_detections()
# ---------------------------------------------------------------------------

class TestRenderDetections:
    def test_empty_message(self):
        assert sync_todo.render_detections({}) == "_No detections shipped yet._"

    def test_renders_table(self):
        dets = {
            "T1059.001": {
                "id": "T1059.001",
                "title": "PowerShell Encoded",
                "backends": {
                    "kql": "detections/kql/T1059.001_ps.md",
                    "sigma": "detections/sigma/T1059.001_ps.md",
                },
            }
        }
        result = sync_todo.render_detections(dets)
        assert "| `T1059.001` |" in result
        assert "PowerShell Encoded" in result
        assert "[" in result  # links


# ---------------------------------------------------------------------------
# Tests: render_simple_list()
# ---------------------------------------------------------------------------

class TestRenderSimpleList:
    def test_empty_shows_message(self, tmp_path: Path):
        result = sync_todo.render_simple_list([], "_Nothing here._")
        assert result == "_Nothing here._"

    def test_renders_checklist(self, tmp_path: Path):
        f = tmp_path / "playbook.md"
        f.write_text("# Phishing Triage\n", encoding="utf-8")

        with patch.object(sync_todo, "REPO", tmp_path):
            result = sync_todo.render_simple_list([f], "_Empty._")
        assert "- [x]" in result
        assert "Phishing Triage" in result


# ---------------------------------------------------------------------------
# Tests: tactic_counts()
# ---------------------------------------------------------------------------

class TestTacticCounts:
    def test_maps_known_techniques(self):
        dets = {
            "T1059.001": {"id": "T1059.001", "title": "PS", "backends": {}},
            "T1566.001": {"id": "T1566.001", "title": "Phish", "backends": {}},
            "T1486": {"id": "T1486", "title": "Ransom", "backends": {}},
        }
        counts = sync_todo.tactic_counts(dets)
        assert counts["execution"] == 1
        assert counts["initial-access"] == 1
        assert counts["impact"] == 1

    def test_unknown_technique_is_unmapped(self):
        dets = {
            "T9999": {"id": "T9999", "title": "Unknown", "backends": {}},
        }
        counts = sync_todo.tactic_counts(dets)
        assert counts["unmapped"] == 1


# ---------------------------------------------------------------------------
# Tests: replace_blocks()
# ---------------------------------------------------------------------------

class TestReplaceBlocks:
    def test_replaces_marker_content(self):
        text = textwrap.dedent("""\
            # Title
            <!-- BEGIN AUTO: summary -->
            old content
            <!-- END AUTO: summary -->
            # Footer
        """)
        blocks = {"summary": "new content"}
        result = sync_todo.replace_blocks(text, blocks)
        assert "new content" in result
        assert "old content" not in result
        assert "# Title" in result
        assert "# Footer" in result

    def test_leaves_unknown_markers_alone(self):
        text = textwrap.dedent("""\
            <!-- BEGIN AUTO: unknown -->
            keep me
            <!-- END AUTO: unknown -->
        """)
        blocks = {"summary": "replaced"}
        result = sync_todo.replace_blocks(text, blocks)
        assert "keep me" in result

    def test_multiple_blocks(self):
        text = textwrap.dedent("""\
            <!-- BEGIN AUTO: a -->
            old-a
            <!-- END AUTO: a -->
            middle
            <!-- BEGIN AUTO: b -->
            old-b
            <!-- END AUTO: b -->
        """)
        blocks = {"a": "new-a", "b": "new-b"}
        result = sync_todo.replace_blocks(text, blocks)
        assert "new-a" in result
        assert "new-b" in result
        assert "old-a" not in result
        assert "old-b" not in result
        assert "middle" in result


# ---------------------------------------------------------------------------
# Tests: render_summary()
# ---------------------------------------------------------------------------

class TestRenderSummary:
    def test_counts_all_areas(self):
        result = sync_todo.render_summary(
            {"T1059": {}},          # 1 detection
            ["cve1", "cve2"],       # 2 CVEs
            ["pb1"],                # 1 playbook
            ["wf1", "wf2", "wf3"], # 3 workflows
            ["actor1"],             # 1 actor
            [],                     # 0 campaigns
            ["ttp1"],               # 1 ttp
            ["lab1", "lab2"],       # 2 labs
            [],                     # 0 hardening
        )
        assert "| Detections (techniques covered) | 1 |" in result
        assert "| Playbooks | 1 |" in result
        assert "| CVE write-ups | 2 |" in result
        assert "| Detection workflows | 3 |" in result
        assert "| Purple-team labs | 2 |" in result


# ---------------------------------------------------------------------------
# Tests: main() (integration-level)
# ---------------------------------------------------------------------------

class TestMain:
    def test_check_mode_passes_when_in_sync(self, tmp_path: Path):
        """--check returns 0 when TODO.md doesn't need changes."""
        todo = tmp_path / "TODO.md"
        todo.write_text("# TODO\nNo auto markers here.\n", encoding="utf-8")

        with patch.object(sync_todo, "REPO", tmp_path):
            with patch.object(sync_todo, "TODO", todo):
                with patch("sys.argv", ["sync-todo.py", "--check"]):
                    result = sync_todo.main()
        assert result == 0

    def test_check_mode_fails_when_out_of_sync(self, tmp_path: Path):
        """--check returns 1 when TODO.md would change."""
        # Create directories the script discovers
        (tmp_path / "detections" / "kql").mkdir(parents=True)
        (tmp_path / "detections" / "kql" / "T1059.001_ps.md").write_text(
            "# PowerShell Encoded Command\n", encoding="utf-8"
        )

        todo = tmp_path / "TODO.md"
        todo.write_text(
            textwrap.dedent("""\
                # TODO
                <!-- BEGIN AUTO: detections -->
                old stale content
                <!-- END AUTO: detections -->
            """),
            encoding="utf-8",
        )

        with patch.object(sync_todo, "REPO", tmp_path):
            with patch.object(sync_todo, "TODO", todo):
                with patch("sys.argv", ["sync-todo.py", "--check"]):
                    result = sync_todo.main()
        assert result == 1
