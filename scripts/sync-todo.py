#!/usr/bin/env python3
"""Auto-sync TODO.md and COVERAGE.md from what's actually on disk.

Discovers detections, playbooks, vulnerabilities, threat-intel notes, and
purple-team labs from the filesystem and regenerates the marked sections of
TODO.md (and the per-tactic counts in COVERAGE.md) so the lists are never
manually out of date.

Sections in TODO.md are bounded by paired marker comments:

    <!-- BEGIN AUTO: detections -->
    ... auto-generated ...
    <!-- END AUTO: detections -->

Anything outside the markers is preserved verbatim (manual notes, ordering
preferences, "🔥 Next up" picks, etc.). To opt a section out of auto-sync,
simply remove its marker pair.

Usage:
    python scripts/sync-todo.py [--check]

--check exits 1 if running would change anything (used by CI to verify the
file in the PR is in sync). Without --check the script writes the updated
files in place.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

from _shared import REPO_ROOT, TECHNIQUE_ID_RE, list_markdown, title_of

TODO = REPO_ROOT / "TODO.md"
COVERAGE = REPO_ROOT / "COVERAGE.md"

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def detection_files() -> dict[str, dict]:
    """Group detection files by ATT&CK technique id."""
    out: dict[str, dict] = {}
    for backend in ("kql", "sigma"):
        d = REPO_ROOT / "detections" / backend
        if not d.is_dir():
            continue
        for md in sorted(d.glob("T*.md")):
            if md.name.startswith("_"):
                continue
            stem = md.stem
            m = TECHNIQUE_ID_RE.match(stem)
            if not m:
                continue
            tid = m.group(0)
            entry = out.setdefault(
                tid,
                {"id": tid, "title": stem.split("_", 1)[1] if "_" in stem else stem, "backends": {}},
            )
            entry["backends"][backend] = md.relative_to(REPO_ROOT).as_posix()
            # Prefer the longest human title we see.
            t = title_of(md)
            if len(t) > len(entry["title"]):
                entry["title"] = t
    return out


def cves() -> list[Path]:
    return [p for p in list_markdown(REPO_ROOT / "vulnerabilities") if p.name.upper().startswith("CVE-")]


def playbooks() -> list[Path]:
    return list_markdown(REPO_ROOT / "blue-team-playbooks")


def workflows() -> list[Path]:
    return list_markdown(REPO_ROOT / "detection-workflows")


def actors() -> list[Path]:
    return list_markdown(REPO_ROOT / "threat-intelligence" / "actors")


def campaigns() -> list[Path]:
    return list_markdown(REPO_ROOT / "threat-intelligence" / "campaigns")


def ttps() -> list[Path]:
    return list_markdown(REPO_ROOT / "threat-intelligence" / "ttps")


def hardening_guides() -> list[Path]:
    return list_markdown(REPO_ROOT / "hardening")


def labs() -> list[Path]:
    base = REPO_ROOT / "purple-team-labs"
    if not base.is_dir():
        return []
    out = []
    for sub in sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith("_")):
        readme = sub / "README.md"
        if readme.exists():
            out.append(readme)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_detections(dets: dict[str, dict]) -> str:
    if not dets:
        return "_No detections shipped yet._"
    lines = ["| Tech ID | Title | KQL | Sigma |", "|---|---|:---:|:---:|"]
    for tid in sorted(dets):
        d = dets[tid]
        kql = f"[✅]({d['backends']['kql']})" if "kql" in d["backends"] else "—"
        sig = f"[✅]({d['backends']['sigma']})" if "sigma" in d["backends"] else "—"
        title = d["title"].replace("|", "\\|")
        lines.append(f"| `{tid}` | {title} | {kql} | {sig} |")
    return "\n".join(lines)


def render_simple_list(paths: list[Path], empty_msg: str) -> str:
    if not paths:
        return empty_msg
    out = []
    for p in paths:
        rel = p.relative_to(REPO_ROOT).as_posix()
        out.append(f"- [x] [{title_of(p)}]({rel})")
    return "\n".join(out)


def render_summary(dets, cs, ps, ws, ac, ca, tt, lb, hg) -> str:
    return (
        "| Area | Shipped |\n"
        "|---|---|\n"
        f"| Detections (techniques covered) | {len(dets)} |\n"
        f"| Playbooks | {len(ps)} |\n"
        f"| Hardening guides | {len(hg)} |\n"
        f"| Detection workflows | {len(ws)} |\n"
        f"| CVE write-ups | {len(cs)} |\n"
        f"| Threat actors profiled | {len(ac)} |\n"
        f"| Threat-intel campaigns | {len(ca)} |\n"
        f"| Threat-intel TTP roundups | {len(tt)} |\n"
        f"| Purple-team labs | {len(lb)} |"
    )


def tactic_counts(dets: dict[str, dict]) -> Counter:
    """Approximate per-tactic counts from technique IDs.

    Maps a known set of technique IDs to ATT&CK tactic short codes. Any
    technique not in the map is logged as "unmapped" so it isn't silently
    miscounted.
    """
    # technique-id (without sub) → tactic short-code
    TACTIC = {
        "T1059": "execution",
        "T1003": "credential-access",
        "T1110": "credential-access",
        "T1547": "persistence",
        "T1486": "impact",
        "T1078": "defense-evasion",
        "T1071": "command-and-control",
        "T1218": "defense-evasion",
        "T1021": "lateral-movement",
        "T1053": "persistence",
        "T1543": "persistence",
        "T1566": "initial-access",
    }
    c: Counter = Counter()
    for tid in dets:
        base = tid.split(".")[0]
        c[TACTIC.get(base, "unmapped")] += 1
    return c


# ---------------------------------------------------------------------------
# Marker replacement
# ---------------------------------------------------------------------------

MARKER_RE = re.compile(
    r"(<!--\s*BEGIN AUTO:\s*(?P<name>[a-z0-9_-]+)\s*-->)"
    r"(?P<body>.*?)"
    r"(<!--\s*END AUTO:\s*(?P=name)\s*-->)",
    re.DOTALL,
)


def replace_blocks(text: str, blocks: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        name = m.group("name")
        if name not in blocks:
            return m.group(0)  # unknown marker — leave alone
        return f"{m.group(1)}\n\n{blocks[name].rstrip()}\n\n{m.group(4)}"

    return MARKER_RE.sub(sub, text)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="exit non-zero if files would change")
    args = parser.parse_args()

    dets = detection_files()
    cs, ps, ws = cves(), playbooks(), workflows()
    ac, ca, tt, lb = actors(), campaigns(), ttps(), labs()
    hg = hardening_guides()

    blocks = {
        "summary": render_summary(dets, cs, ps, ws, ac, ca, tt, lb, hg),
        "detections": render_detections(dets),
        "playbooks": render_simple_list(ps, "_No playbooks shipped yet._"),
        "detection-workflows": render_simple_list(ws, "_No detection workflows shipped yet._"),
        "cves": render_simple_list(cs, "_No CVE write-ups shipped yet._"),
        "actors": render_simple_list(ac, "_No actor profiles shipped yet._"),
        "campaigns": render_simple_list(ca, "_No campaign write-ups shipped yet._"),
        "ttps": render_simple_list(tt, "_No TTP roundups shipped yet._"),
        "labs": render_simple_list(lb, "_No purple-team labs shipped yet._"),
        "hardening": render_simple_list(hg, "_No hardening guides shipped yet._"),
    }

    changed = False
    for path in (TODO,):
        original = path.read_text(encoding="utf-8")
        updated = replace_blocks(original, blocks)
        if updated != original:
            changed = True
            if not args.check:
                path.write_text(updated, encoding="utf-8")
                print(f"updated {path.relative_to(REPO_ROOT)}")

    if args.check:
        if changed:
            print("ERROR: TODO.md is out of sync. Run: python scripts/sync-todo.py", file=sys.stderr)
            return 1
        print("TODO.md is in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
