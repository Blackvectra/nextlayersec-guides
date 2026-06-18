"""Shared fixtures for the nextlayersec-guides test suite."""
from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def tmp_repo(tmp_path: Path) -> Path:
    """Create a minimal fake repo tree for testing file-walk logic."""
    return tmp_path


@pytest.fixture()
def fake_vuln_dir(tmp_path: Path) -> Path:
    """Create a vulnerabilities/ directory with sample CVE files."""
    vuln = tmp_path / "vulnerabilities"
    vuln.mkdir()

    # Good file — CVE in filename matches body
    (vuln / "CVE-2024-12345.md").write_text(
        textwrap.dedent("""\
            # CVE-2024-12345

            A critical vulnerability in Widgets Corp.
            References: CVE-2024-12345
        """),
        encoding="utf-8",
    )

    # Bad file — filename says 2024 but body says 2023
    (vuln / "CVE-2024-99999.md").write_text(
        textwrap.dedent("""\
            # CVE-2023-99999

            Copy-paste mistake — wrong CVE in the body.
        """),
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture()
def fake_md_tree(tmp_path: Path) -> Path:
    """Create a directory tree with markdown files and links."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")

    # File with a valid internal link
    (tmp_path / "good.md").write_text(
        "[Guide](docs/guide.md)\n",
        encoding="utf-8",
    )

    # File with a broken internal link
    (tmp_path / "broken.md").write_text(
        "[Missing](docs/nonexistent.md)\n",
        encoding="utf-8",
    )

    # File with external link (should be skipped)
    (tmp_path / "external.md").write_text(
        "[GitHub](https://github.com)\n",
        encoding="utf-8",
    )

    return tmp_path
