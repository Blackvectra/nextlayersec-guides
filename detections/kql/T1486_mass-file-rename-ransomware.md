# Mass File Rename — Ransomware Encryption Canary

- **Query file:** `T1486_mass-file-rename-ransomware.kql`
- **Author:** nextlayersec
- **Last updated:** 2026-05-27
- **Status:** testing
- **Severity:** Critical

## What it detects

A single process renaming a large number of files across multiple directories in a short window, with **many distinct source extensions collapsing into a single destination extension** — the canonical ransomware encryption pattern (e.g., everything turning into `.locked`, `.crypt`, `.<actor>`, or a per-victim suffix).

## ATT&CK mapping

- **Tactic:** Impact (TA0040)
- **Technique:** T1486 – Data Encrypted for Impact
- **Related:** T1490 – Inhibit System Recovery (shadow copy deletion usually fires alongside)

## Data sources

- Table: `DeviceFileEvents` with `ActionType == "FileRenamed"` (Defender for Endpoint)
- Equivalent: Sysmon Event ID 11/23 (file create/delete) plus rename inference
- Retention recommendation: 30 days

## Logic

Groups rename events by `(DeviceName, InitiatingProcess)` over a 15-minute window. Requires **all three**: ≥ 50 files touched, ≥ 5 distinct source extensions, ≥ 3 distinct directories. The multi-extension constraint filters out archivers, transcoders, and build tools that touch many same-type files.

## False positives

- Bulk migration / cleanup scripts run by IT.
- Backup / DLP agents performing scheduled transformations.
- Photo or media library reorganization tools.
- Suppress by adding the legitimate process to a per-host or per-user allowlist.

## Tuning

- Lower `fileThreshold` if your environment has small user file footprints — speed matters more than precision once ransomware is running.
- Add a join on `DeviceProcessEvents` to enrich with parent process (most ransomware spawns from PowerShell, rundll32, or an Office macro).
- Pair with [`T1059.001_powershell-encoded-command`](T1059.001_powershell-encoded-command.md) — co-firing is near-certain ransomware.

## Response

**This is a contain-now alert.** See [`blue-team-playbooks/phishing-email-triage.md`](../../blue-team-playbooks/phishing-email-triage.md) for the upstream initial-access pattern; the dedicated ransomware playbook is on the roadmap. Immediate actions:

1. Isolate host via EDR (do not log off — preserve memory).
2. Identify and disable accounts used by the encrypting process.
3. Block lateral movement (firewall RDP / SMB to the host).
4. Snapshot memory and key directories before reimaging.
5. Begin scoping: file shares, backups, identity blast radius.

## References

- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
- CISA #StopRansomware guides: https://www.cisa.gov/stopransomware
