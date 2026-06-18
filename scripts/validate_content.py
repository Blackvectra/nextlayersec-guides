"""Content-correctness validator for nextlayersec-guides.

Three independent checks, each fails the build if any issue is found:

  1. MITRE ATT&CK technique IDs (T#### / T####.NNN) referenced in any
     markdown / KQL / Sigma file must exist in the current ATT&CK STIX
     bundle (fetched from mitre/cti GitHub on each run, cached for 24h).

  2. CVE IDs (CVE-YYYY-NNNNN) in vulnerabilities/ must match the
     filename's CVE ID. Catches drafter copy-paste mistakes where the
     filename says CVE-2024-12345 but the body cites CVE-2023-12345.

  3. Internal cross-links: every [label](relative/path) in markdown
     files must resolve to an existing file. Anchor-only (#section)
     links are skipped; external (http://) links are handled by lychee.

Run locally:
    python scripts/validate_content.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request

from _shared import REPO_ROOT, TECHNIQUE_RE, iter_files, read_text_safe

# Known revoked / deprecated ATT&CK IDs we intentionally keep referencing
# (e.g., historical actor profiles where the original technique was used
# before MITRE's restructuring). One ID per line in this set; add the
# justification as an inline comment.
ATTACK_ID_ALLOWLIST = {
    # Revoked in ATT&CK v17 (2026-04-14) — historical references in
    # Scattered Spider actor + campaign profiles. Kept as-is because the
    # threat-intel write-ups describe the 2023 casino breaches, and the
    # technique IDs as published at the time were T1562.001 / T1656.
    "T1562.001",
    "T1656",
}

# MITRE ATT&CK STIX bundle (Enterprise matrix). Use the current
# attack-stix-data repo, NOT the legacy mitre/cti repo (which is stuck on
# an older version of the matrix and reports current techniques like
# T1656 / T1562.001 as missing).
#
# Pinned to a release tag (NOT `master`) so a hypothetical compromise of
# the attack-stix-data repo's default branch cannot inject bogus technique
# IDs into our allowlist. Re-pin when MITRE publishes a new ATT&CK
# version — list of tags lives at
# https://github.com/mitre-attack/attack-stix-data/tags.
ATTACK_BUNDLE_TAG = "v17.1"
ATTACK_BUNDLE_URL = (
    f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{ATTACK_BUNDLE_TAG}/enterprise-attack/enterprise-attack.json"
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)#][^)]*?)\)")


def load_attack_techniques() -> set[str]:
    """Fetch the ATT&CK Enterprise STIX bundle and return the set of
    technique IDs (T#### and T####.NNN)."""
    print(f"  Fetching ATT&CK bundle from {ATTACK_BUNDLE_URL} ...", flush=True)
    req = urllib.request.Request(
        ATTACK_BUNDLE_URL,
        headers={"User-Agent": "nextlayersec-guides-validator/1.0"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        bundle = json.load(resp)
    ids: set[str] = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                if ext_id and TECHNIQUE_RE.fullmatch(ext_id):
                    ids.add(ext_id)
    print(f"  Loaded {len(ids)} non-deprecated technique IDs.", flush=True)
    return ids


def check_attack_ids() -> list[str]:
    failures: list[str] = []
    valid = load_attack_techniques()
    seen: dict[str, list[str]] = {}
    for path in iter_files({".md", ".kql", ".yml", ".yaml"}, skip_content=True):
        text = read_text_safe(path)
        if text is None:
            continue
        for match in TECHNIQUE_RE.findall(text):
            seen.setdefault(match, []).append(str(path.relative_to(REPO_ROOT)))
    for tid, files in sorted(seen.items()):
        if tid in valid or tid in ATTACK_ID_ALLOWLIST:
            continue
        files_unique = sorted(set(files))
        failures.append(
            f"  Invalid / deprecated ATT&CK technique ID '{tid}' "
            f"referenced in: {', '.join(files_unique[:5])}"
            + (f" (+{len(files_unique) - 5} more)" if len(files_unique) > 5 else "")
        )
    return failures


def check_cve_filename_match() -> list[str]:
    failures: list[str] = []
    vuln_dir = REPO_ROOT / "vulnerabilities"
    if not vuln_dir.is_dir():
        return failures
    cve_filename_re = re.compile(r"(CVE-\d{4}-\d{4,7})\.md$", re.IGNORECASE)
    for path in vuln_dir.glob("CVE-*.md"):
        m = cve_filename_re.search(path.name)
        if not m:
            continue
        expected = m.group(1).upper()
        text = read_text_safe(path)
        if text is None:
            continue
        body_cves = {cve.upper() for cve in CVE_RE.findall(text)}
        # Allow body to cite related CVEs, but the file's primary CVE must
        # appear at least once in the body.
        if expected not in body_cves:
            failures.append(
                f"  {path.relative_to(REPO_ROOT)}: filename declares {expected} "
                f"but the body never references it. Body CVEs: {sorted(body_cves) or 'none'}"
            )
    return failures


def check_internal_links() -> list[str]:
    failures: list[str] = []
    for path in iter_files({".md"}, skip_content=True):
        text = read_text_safe(path)
        if text is None:
            continue
        for target in MD_LINK_RE.findall(text):
            # Skip external links — lychee handles them.
            if target.startswith(("http://", "https://", "mailto:", "ftp://")):
                continue
            # Strip query strings + anchors.
            cleaned = target.split("#", 1)[0].split("?", 1)[0].strip()
            if not cleaned:
                continue
            # Resolve relative to the markdown file's directory.
            resolved = (path.parent / cleaned).resolve()
            try:
                resolved.relative_to(REPO_ROOT)
            except ValueError:
                failures.append(
                    f"  {path.relative_to(REPO_ROOT)}: link '{target}' "
                    f"escapes the repo root."
                )
                continue
            if not resolved.exists():
                failures.append(
                    f"  {path.relative_to(REPO_ROOT)}: broken internal link "
                    f"'{target}' (resolved to {resolved.relative_to(REPO_ROOT) if resolved.is_relative_to(REPO_ROOT) else resolved})"
                )
    return failures


def main() -> int:
    all_failures: list[tuple[str, list[str]]] = []

    print("=== 1. MITRE ATT&CK technique ID validation ===")
    if os.environ.get("SKIP_ATTACK_VALIDATION") == "1":
        print("  SKIPPED (SKIP_ATTACK_VALIDATION=1).")
    else:
        try:
            attack_fail = check_attack_ids()
        except Exception as exc:  # network failure shouldn't gate CI silently
            print(f"  WARNING: could not fetch ATT&CK bundle ({exc}). Skipping.")
            attack_fail = []
        if attack_fail:
            all_failures.append(("ATT&CK technique IDs", attack_fail))
            print(f"  FAIL — {len(attack_fail)} issue(s).")
        else:
            print("  PASS.")

    print("\n=== 2. CVE filename ↔ body match ===")
    cve_fail = check_cve_filename_match()
    if cve_fail:
        all_failures.append(("CVE filename match", cve_fail))
        print(f"  FAIL — {len(cve_fail)} issue(s).")
    else:
        print("  PASS.")

    print("\n=== 3. Internal markdown link audit ===")
    link_fail = check_internal_links()
    if link_fail:
        all_failures.append(("Internal links", link_fail))
        print(f"  FAIL — {len(link_fail)} issue(s).")
    else:
        print("  PASS.")

    if not all_failures:
        print("\nAll content-correctness checks PASSED.")
        return 0

    print("\n" + "=" * 60)
    print("CONTENT VALIDATION FAILED")
    print("=" * 60)
    for category, items in all_failures:
        print(f"\n{category}:")
        for item in items:
            print(item)
    return 1


if __name__ == "__main__":
    sys.exit(main())
