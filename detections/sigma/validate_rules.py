#!/usr/bin/env python3
"""Validate every non-template Sigma rule under detections/sigma/.

Run locally exactly as CI does:

    pip install pysigma
    python detections/sigma/validate_rules.py

Exits non-zero if any rule fails to parse, and prints a clear per-file result
plus the environment versions for debugging.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/ importable so we can reuse the shared helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))
from _shared import REPO_ROOT, is_template  # noqa: E402

SIGMA_DIR = REPO_ROOT / "detections" / "sigma"


def main() -> int:
    print(f"python: {sys.version.split()[0]}")
    try:
        import sigma  # noqa: F401
        from sigma.collection import SigmaCollection
    except Exception as exc:  # import / install problem
        print(f"FATAL: could not import pySigma: {exc}")
        return 2

    try:
        from importlib.metadata import version

        print(f"pySigma: {version('pysigma')}")
    except Exception as exc:
        print(f"WARNING: could not determine pySigma version: {exc}")

    rules = [
        p
        for p in sorted(SIGMA_DIR.glob("*.yml"))
        if not is_template(p)
    ]
    if not rules:
        print("No Sigma rules found under detections/sigma/ (nothing to validate).")
        return 0

    failed = False
    for path in rules:
        try:
            SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
            print(f"OK   {path.relative_to(REPO_ROOT)}")
        except Exception as exc:
            failed = True
            print(f"FAIL {path.relative_to(REPO_ROOT)}: {type(exc).__name__}: {exc}")

    print("=== ALL PASS ===" if not failed else "=== VALIDATION FAILED ===")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
