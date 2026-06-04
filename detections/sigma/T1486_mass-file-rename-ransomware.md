# Mass File Rename — Ransomware Encryption Canary (Sigma)

- **Query file:** `T1486_mass-file-rename-ransomware.yml`
- **Author:** nextlayersec
- **Last updated:** 2026-05-28
- **Status:** experimental
- **Severity:** Critical

## What it detects

A single process renaming a large number of files on one host in a short window — the canonical ransomware encryption pattern (everything turning into `.locked`, `.crypt`, `.<actor>`, or a per-victim suffix). The rule ships as two YAML documents: a noisy base rule that matches file rename events, and a correlation rule that fires once one process crosses a rename-count threshold.

## ATT&CK mapping

- **Tactic:** Impact (TA0040)
- **Technique:** T1486 – Data Encrypted for Impact
- **Related:** T1490 – Inhibit System Recovery (shadow copy deletion usually fires alongside)

## Data sources

- Log source: `file_event` (Windows)
- Sysmon: Event ID 11 (FileCreate) / 23 (FileDelete) rename semantics — `EventType: Rename`
- Defender XDR / MDE: `DeviceFileEvents` with `ActionType == "FileRenamed"`
- Sentinel: same `DeviceFileEvents` table via the M365D connector
- Minimum retention recommended: 30 days

## Logic

The base rule (`name: file_rename_event`) matches file rename events (`EventType: Rename`). On its own this is benign and high-volume. The correlation rule references it by name and applies an `event_count` grouped by `Image` + `Computer`, firing when `gte: 50` rename events are seen within `timespan: 15m`.

### SIEM-side aggregation

Sigma correlation rules require a backend that supports the correlation extension. For backends without native correlation support, port the threshold to a stateful query yourself:

- **Group key:** `Image`, `Computer`
- **Counted field:** rename events (total count)
- **Threshold:** ≥ 50 renames
- **Window:** 15 minutes (sliding)

In Sentinel KQL this becomes a `summarize count() by Image, Computer, bin(TimeGenerated, 15m)` followed by `where count_ >= 50`. In Splunk, `stats count by Image, Computer` inside a 15m time window with `where count>=50`. Convert with `sigma convert -t <backend> detections/sigma/T1486_mass-file-rename-ransomware.yml` — backends that lack correlation support will emit the base rule and warn; apply the aggregation above manually there.

## False positives

- Bulk migration or cleanup scripts run by IT.
- Backup or DLP agents performing scheduled transformations.
- Photo or media library reorganization tools.

## Tuning

- Lower the `gte` threshold if your environment has small user file footprints — speed matters more than precision once ransomware is running.
- Add the legitimate process to a per-host or per-user allowlist on the backend.
- Pair with [`T1059.001_powershell-encoded-command`](T1059.001_powershell-encoded-command.md) — co-firing is near-certain ransomware.

## Response

**This is a contain-now alert.** Immediate actions:

1. Isolate host via EDR (do not log off — preserve memory).
2. Identify and disable accounts used by the encrypting process.
3. Block lateral movement (firewall RDP / SMB to the host).
4. Snapshot memory and key directories before reimaging.
5. Begin scoping: file shares, backups, identity blast radius.

## References

- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
- Sibling KQL note: [`T1486_mass-file-rename-ransomware`](../kql/T1486_mass-file-rename-ransomware.md)
- CISA #StopRansomware guides: https://www.cisa.gov/stopransomware
