#!/usr/bin/env python3
"""Validate every non-template Sigma rule under detections/sigma/.

Run locally exactly as CI does:

    pip install pysigma
    python detections/sigma/validate_rules.py

Exits non-zero if any rule fails to parse, and prints a clear per-file result
plus the environment versions for debugging.
"""
from __future__ import annotations

import glob
import os
import sys


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
    except Exception:
        pass

    rules = [
        p
        for p in sorted(glob.glob("detections/sigma/*.yml"))
        if not os.path.basename(p).startswith("_")
    ]
    if not rules:
        print("No Sigma rules found under detections/sigma/ (nothing to validate).")
        return 0

    failed = False
    for path in rules:
        try:
            with open(path, encoding="utf-8") as fh:
                SigmaCollection.from_yaml(fh.read())
            print(f"OK   {path}")
        except Exception as exc:
            failed = True
            print(f"FAIL {path}: {type(exc).__name__}: {exc}")

    print("=== ALL PASS ===" if not failed else "=== VALIDATION FAILED ===")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
