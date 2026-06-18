"""Shared utilities for nextlayersec-guides scripts.

Consolidates file-iteration helpers, regex patterns, and path
constants that were previously duplicated across validate_content.py,
sync-todo.py, and detections/sigma/validate_rules.py.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories to skip when recursively walking the repo.
SKIP_PATHS: set[str] = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "_docs",
    "site",
}

# Paths excluded from content-correctness scanning (config / tooling / meta,
# not security content).
SKIP_FOR_CONTENT: set[str] = {
    ".github",
    "scripts",
    "CHANGELOG.md",
    "TODO.md",
}

# Word-boundary delimited — for scanning free text / prose.
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# No trailing word boundary — for extracting IDs from filenames where
# the technique ID is followed by an underscore (e.g. T1003.001_lsass…).
TECHNIQUE_ID_RE = re.compile(r"T(\d{4}(?:\.\d{3})?)")

TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def is_template(path: Path) -> bool:
    """Return True if *path* is a template file (name starts with ``_``)."""
    return path.name.startswith("_")


def read_text_safe(path: Path) -> str | None:
    """Read *path* as UTF-8, returning ``None`` on decode errors."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def title_of(md_path: Path) -> str:
    """Extract the first ``# ...`` heading from a markdown file.

    Falls back to the file stem on any error.
    """
    try:
        text = md_path.read_text(encoding="utf-8")
        m = TITLE_RE.search(text)
        return m.group(1).strip() if m else md_path.stem
    except Exception:
        return md_path.stem


def iter_files(
    extensions: set[str],
    *,
    skip_content: bool = False,
    root: Path | None = None,
) -> Iterator[Path]:
    """Yield repo files matching *extensions*, skipping non-content paths.

    Parameters
    ----------
    extensions:
        File suffixes to include (e.g. ``{".md", ".kql"}``).
    skip_content:
        When True, also skip paths listed in :data:`SKIP_FOR_CONTENT`.
    root:
        Starting directory.  Defaults to :data:`REPO_ROOT`.
    """
    base = root or REPO_ROOT
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.is_symlink():
            continue
        if any(part in SKIP_PATHS for part in path.parts):
            continue
        if skip_content:
            rel_parts = path.relative_to(REPO_ROOT).parts
            if rel_parts and rel_parts[0] in SKIP_FOR_CONTENT:
                continue
        if path.suffix.lower() in extensions:
            yield path


def list_markdown(
    dir_path: Path,
    predicate: Callable[[Path], bool] | None = None,
) -> list[Path]:
    """List non-template, non-README markdown files in *dir_path*.

    Parameters
    ----------
    dir_path:
        Directory to scan (non-recursive).
    predicate:
        Optional callable ``(Path) -> bool`` for extra filtering.
    """
    if not dir_path.is_dir():
        return []
    files: list[Path] = []
    for p in sorted(dir_path.glob("*.md")):
        if is_template(p):
            continue
        if p.name.lower() == "readme.md":
            continue
        if predicate and not predicate(p):
            continue
        files.append(p)
    return files
