"""Unit tests for scripts/validate_content.py.

Tests cover:
  - iter_files() filtering logic
  - check_attack_ids() (mocked network)
  - check_cve_filename_match()
  - check_internal_links()
  - main() orchestration
"""
from __future__ import annotations

import importlib
import json
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import the module under test — we need to manipulate REPO_ROOT for testing
# so we import it dynamically and patch REPO_ROOT where needed.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_content  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_stix_bundle(techniques: list[dict]) -> dict:
    """Create a minimal STIX bundle with the given technique objects."""
    objects = []
    for t in techniques:
        obj = {
            "type": "attack-pattern",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": t["id"]}
            ],
        }
        if t.get("revoked"):
            obj["revoked"] = True
        if t.get("deprecated"):
            obj["x_mitre_deprecated"] = True
        objects.append(obj)
    return {"objects": objects}


# ---------------------------------------------------------------------------
# Tests: TECHNIQUE_RE
# ---------------------------------------------------------------------------

class TestTechniqueRegex:
    def test_matches_base_technique(self):
        assert validate_content.TECHNIQUE_RE.findall("T1059") == ["T1059"]

    def test_matches_subtechnique(self):
        assert validate_content.TECHNIQUE_RE.findall("T1059.001") == ["T1059.001"]

    def test_multiple_in_text(self):
        text = "Covers T1566.001 and T1071.001 plus T1486"
        assert set(validate_content.TECHNIQUE_RE.findall(text)) == {
            "T1566.001", "T1071.001", "T1486"
        }

    def test_no_match_on_short_id(self):
        assert validate_content.TECHNIQUE_RE.findall("T123") == []

    def test_no_match_on_non_T_prefix(self):
        assert validate_content.TECHNIQUE_RE.findall("A1234") == []


# ---------------------------------------------------------------------------
# Tests: CVE_RE
# ---------------------------------------------------------------------------

class TestCveRegex:
    def test_matches_standard_cve(self):
        assert validate_content.CVE_RE.findall("CVE-2024-12345") == ["CVE-2024-12345"]

    def test_matches_short_cve(self):
        assert validate_content.CVE_RE.findall("CVE-2024-1234") == ["CVE-2024-1234"]

    def test_matches_long_cve(self):
        assert validate_content.CVE_RE.findall("CVE-2024-1234567") == ["CVE-2024-1234567"]

    def test_no_match_too_short(self):
        assert validate_content.CVE_RE.findall("CVE-2024-123") == []


# ---------------------------------------------------------------------------
# Tests: MD_LINK_RE
# ---------------------------------------------------------------------------

class TestMdLinkRegex:
    def test_matches_relative_path(self):
        assert validate_content.MD_LINK_RE.findall("[Go](docs/file.md)") == ["docs/file.md"]

    def test_skips_anchor_only(self):
        assert validate_content.MD_LINK_RE.findall("[Section](#section)") == []

    def test_external_link_captured(self):
        # Note: the regex captures it; the check_internal_links function skips it
        assert validate_content.MD_LINK_RE.findall("[Site](https://example.com)") == ["https://example.com"]


# ---------------------------------------------------------------------------
# Tests: iter_files()
# ---------------------------------------------------------------------------

class TestIterFiles:
    def test_finds_markdown_files(self, tmp_path: Path):
        (tmp_path / "file.md").write_text("# Hello", encoding="utf-8")
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "deep.md").write_text("# Deep", encoding="utf-8")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            found = list(validate_content.iter_files({".md"}))
        assert len(found) == 2

    def test_skips_git_directory(self, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config.md").write_text("# Git", encoding="utf-8")
        (tmp_path / "real.md").write_text("# Real", encoding="utf-8")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            found = list(validate_content.iter_files({".md"}))
        assert len(found) == 1
        assert found[0].name == "real.md"

    def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "package.md").write_text("# Pkg", encoding="utf-8")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            found = list(validate_content.iter_files({".md"}))
        assert len(found) == 0

    def test_skip_content_flag(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "helper.md").write_text("# Helper", encoding="utf-8")
        (tmp_path / "real.md").write_text("# Real", encoding="utf-8")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            found = list(validate_content.iter_files({".md"}, skip_content=True))
        names = [f.name for f in found]
        assert "real.md" in names
        assert "helper.md" not in names

    def test_filters_by_extension(self, tmp_path: Path):
        (tmp_path / "file.md").write_text("md", encoding="utf-8")
        (tmp_path / "file.py").write_text("py", encoding="utf-8")
        (tmp_path / "file.kql").write_text("kql", encoding="utf-8")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            found = list(validate_content.iter_files({".md", ".kql"}))
        extensions = {f.suffix for f in found}
        assert extensions == {".md", ".kql"}

    def test_skips_symlinks(self, tmp_path: Path):
        (tmp_path / "real.md").write_text("# Real", encoding="utf-8")
        (tmp_path / "link.md").symlink_to(tmp_path / "real.md")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            found = list(validate_content.iter_files({".md"}))
        assert len(found) == 1
        assert found[0].name == "real.md"


# ---------------------------------------------------------------------------
# Tests: check_cve_filename_match()
# ---------------------------------------------------------------------------

class TestCheckCveFilenameMatch:
    def test_passes_when_cve_matches(self, tmp_path: Path):
        vuln = tmp_path / "vulnerabilities"
        vuln.mkdir()
        (vuln / "CVE-2024-12345.md").write_text(
            "# CVE-2024-12345\nDescription of CVE-2024-12345.\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            failures = validate_content.check_cve_filename_match()
        assert failures == []

    def test_fails_when_cve_mismatches(self, tmp_path: Path):
        vuln = tmp_path / "vulnerabilities"
        vuln.mkdir()
        (vuln / "CVE-2024-99999.md").write_text(
            "# CVE-2023-99999\nWrong CVE in body.\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            failures = validate_content.check_cve_filename_match()
        assert len(failures) == 1
        assert "CVE-2024-99999" in failures[0]

    def test_empty_when_no_vuln_dir(self, tmp_path: Path):
        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            failures = validate_content.check_cve_filename_match()
        assert failures == []

    def test_allows_multiple_cves_in_body(self, tmp_path: Path):
        vuln = tmp_path / "vulnerabilities"
        vuln.mkdir()
        (vuln / "CVE-2024-11111.md").write_text(
            "# CVE-2024-11111\nRelated: CVE-2024-22222, CVE-2024-11111.\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            failures = validate_content.check_cve_filename_match()
        assert failures == []


# ---------------------------------------------------------------------------
# Tests: check_internal_links()
# ---------------------------------------------------------------------------

class TestCheckInternalLinks:
    def test_valid_link_passes(self, tmp_path: Path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("# Guide", encoding="utf-8")
        (tmp_path / "index.md").write_text("[Guide](docs/guide.md)\n", encoding="utf-8")

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                failures = validate_content.check_internal_links()
        assert failures == []

    def test_broken_link_fails(self, tmp_path: Path):
        (tmp_path / "broken.md").write_text(
            "[Missing](docs/nonexistent.md)\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                failures = validate_content.check_internal_links()
        assert len(failures) == 1
        assert "nonexistent.md" in failures[0]

    def test_external_links_skipped(self, tmp_path: Path):
        (tmp_path / "links.md").write_text(
            "[GitHub](https://github.com)\n[Mail](mailto:a@b.com)\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                failures = validate_content.check_internal_links()
        assert failures == []

    def test_anchor_only_link_skipped(self, tmp_path: Path):
        (tmp_path / "page.md").write_text(
            "[Section](#overview)\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                failures = validate_content.check_internal_links()
        assert failures == []

    def test_link_escaping_repo_root(self, tmp_path: Path):
        (tmp_path / "escape.md").write_text(
            "[Evil](../../etc/passwd)\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                failures = validate_content.check_internal_links()
        assert len(failures) == 1
        assert "escapes the repo root" in failures[0]


# ---------------------------------------------------------------------------
# Tests: load_attack_techniques() (mocked network)
# ---------------------------------------------------------------------------

class TestLoadAttackTechniques:
    def test_extracts_technique_ids(self):
        bundle = _make_stix_bundle([
            {"id": "T1059"},
            {"id": "T1059.001"},
            {"id": "T1566"},
        ])
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read = lambda: json.dumps(bundle).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = mock_resp
            # json.load reads from file-like, so mock accordingly
            with patch("json.load", return_value=bundle):
                ids = validate_content.load_attack_techniques()

        assert "T1059" in ids
        assert "T1059.001" in ids
        assert "T1566" in ids

    def test_excludes_revoked(self):
        bundle = _make_stix_bundle([
            {"id": "T1059"},
            {"id": "T9999", "revoked": True},
        ])

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            with patch("json.load", return_value=bundle):
                ids = validate_content.load_attack_techniques()

        assert "T1059" in ids
        assert "T9999" not in ids

    def test_excludes_deprecated(self):
        bundle = _make_stix_bundle([
            {"id": "T1059"},
            {"id": "T8888", "deprecated": True},
        ])

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            with patch("json.load", return_value=bundle):
                ids = validate_content.load_attack_techniques()

        assert "T1059" in ids
        assert "T8888" not in ids


# ---------------------------------------------------------------------------
# Tests: check_attack_ids() (mocked)
# ---------------------------------------------------------------------------

class TestCheckAttackIds:
    def test_passes_when_all_ids_valid(self, tmp_path: Path):
        (tmp_path / "detection.md").write_text(
            "# T1059.001 PowerShell\nDetection for T1059.001.\n",
            encoding="utf-8",
        )

        valid_ids = {"T1059", "T1059.001"}
        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                with patch.object(validate_content, "load_attack_techniques", return_value=valid_ids):
                    failures = validate_content.check_attack_ids()
        assert failures == []

    def test_fails_on_invalid_id(self, tmp_path: Path):
        (tmp_path / "detection.md").write_text(
            "# T9999 Fake\nDetection for T9999.\n",
            encoding="utf-8",
        )

        valid_ids = {"T1059", "T1059.001"}
        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                with patch.object(validate_content, "load_attack_techniques", return_value=valid_ids):
                    failures = validate_content.check_attack_ids()
        assert len(failures) == 1
        assert "T9999" in failures[0]

    def test_allowlisted_ids_pass(self, tmp_path: Path):
        (tmp_path / "actor.md").write_text(
            "Uses T1562.001 and T1656 techniques.\n",
            encoding="utf-8",
        )

        valid_ids = {"T1059"}
        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.object(validate_content, "SKIP_FOR_CONTENT", set()):
                with patch.object(validate_content, "load_attack_techniques", return_value=valid_ids):
                    failures = validate_content.check_attack_ids()
        assert failures == []


# ---------------------------------------------------------------------------
# Tests: main()
# ---------------------------------------------------------------------------

class TestMain:
    def test_main_all_pass(self, tmp_path: Path):
        """main() returns 0 when all checks pass on an empty repo."""
        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.dict("os.environ", {"SKIP_ATTACK_VALIDATION": "1"}):
                result = validate_content.main()
        assert result == 0

    def test_main_cve_failure(self, tmp_path: Path):
        """main() returns 1 when CVE check finds issues."""
        vuln = tmp_path / "vulnerabilities"
        vuln.mkdir()
        (vuln / "CVE-2024-99999.md").write_text(
            "# Wrong CVE\nNo matching CVE here.\n",
            encoding="utf-8",
        )

        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.dict("os.environ", {"SKIP_ATTACK_VALIDATION": "1"}):
                result = validate_content.main()
        assert result == 1

    def test_skip_attack_validation_env(self, tmp_path: Path):
        """SKIP_ATTACK_VALIDATION=1 skips ATT&CK check."""
        with patch.object(validate_content, "REPO_ROOT", tmp_path):
            with patch.dict("os.environ", {"SKIP_ATTACK_VALIDATION": "1"}):
                with patch.object(validate_content, "load_attack_techniques") as mock_load:
                    validate_content.main()
        mock_load.assert_not_called()
