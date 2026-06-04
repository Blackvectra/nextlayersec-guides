# Detection Data Sources

Telemetry each detection in this repo depends on. Use this to confirm you are
ingesting the right tables / event IDs before deploying a rule, and to scope a
gap analysis ("which detections can I even run today?").

Values are pulled from each rule's KQL and Sigma `.md` siblings.

## Matrix

| Detection | Defender XDR table | Sentinel table | Sysmon EID | Entra connector | Min retention |
|-----------|--------------------|----------------|------------|-----------------|---------------|
| [T1059.001 PowerShell encoded command](kql/T1059.001_powershell-encoded-command.md) | `DeviceProcessEvents` | `SecurityEvent` (EID 4688) / `DeviceProcessEvents` | EID 1 (process creation) | — | 30 days |
| [T1003.001 LSASS access](kql/T1003.001_lsass-access-suspicious.md) | `DeviceEvents` (`ActionType == "OpenProcessApiCall"`) | `DeviceEvents` (M365D connector) | EID 10 (ProcessAccess) | — | 30 days |
| [T1110.003 Entra password spray](kql/T1110.003_entra-password-spray.md) | `AADSignInEventsBeta` (advanced hunting) | `SigninLogs` | — (cloud identity) | Diagnostic settings → Log Analytics | 90 days |
| [T1486 Mass file rename](kql/T1486_mass-file-rename-ransomware.md) | `DeviceFileEvents` (`ActionType == "FileRenamed"`) | `DeviceFileEvents` (M365D connector) | EID 11 / 23 (rename) | — | 30 days |

## Per-rule detail

### T1059.001 — PowerShell encoded command

- **Sigma log source:** `process_creation` (Windows)
- **Defender XDR / MDE:** `DeviceProcessEvents`
- **Sentinel:** `SecurityEvent` EventID 4688 with `CommandLine`, or `DeviceProcessEvents` via the M365D connector
- **Sysmon:** Event ID 1 (process creation)
- **Entra connector:** not applicable
- **Minimum retention:** 30 days
- **Rules:** [`kql/T1059.001_powershell-encoded-command.md`](kql/T1059.001_powershell-encoded-command.md) · [`sigma/T1059.001_powershell-encoded-command.md`](sigma/T1059.001_powershell-encoded-command.md)

### T1003.001 — Suspicious LSASS access

- **Sigma log source:** `process_access` (Windows)
- **Defender XDR / MDE:** `DeviceEvents` with `ActionType == "OpenProcessApiCall"`
- **Sentinel:** same `DeviceEvents` table via the M365D connector
- **Sysmon:** Event ID 10 (ProcessAccess) — primary source; `GrantedAccess`, `SourceImage`, `TargetImage` come from EID 10
- **Entra connector:** not applicable
- **Minimum retention:** 30 days
- **Rules:** [`kql/T1003.001_lsass-access-suspicious.md`](kql/T1003.001_lsass-access-suspicious.md) · [`sigma/T1003.001_lsass-access-suspicious.md`](sigma/T1003.001_lsass-access-suspicious.md)

### T1110.003 — Entra ID password spray

- **Sigma log source:** `azure` / `signinlogs`
- **Defender XDR / MDE:** `AADSignInEventsBeta` (advanced hunting)
- **Sentinel:** `SigninLogs`
- **Sysmon:** not applicable (cloud identity source)
- **Entra connector:** sign-in logs exported via diagnostic settings → Log Analytics / Sentinel
- **Minimum retention:** 90 days
- **Rules:** [`kql/T1110.003_entra-password-spray.md`](kql/T1110.003_entra-password-spray.md) · [`sigma/T1110.003_entra-password-spray.md`](sigma/T1110.003_entra-password-spray.md)

### T1486 — Mass file rename (ransomware canary)

- **Sigma log source:** `file_event` (Windows)
- **Defender XDR / MDE:** `DeviceFileEvents` with `ActionType == "FileRenamed"`
- **Sentinel:** same `DeviceFileEvents` table via the M365D connector
- **Sysmon:** Event ID 11 (FileCreate) / 23 (FileDelete) rename semantics
- **Entra connector:** not applicable
- **Minimum retention:** 30 days
- **Rules:** [`kql/T1486_mass-file-rename-ransomware.md`](kql/T1486_mass-file-rename-ransomware.md) · [`sigma/T1486_mass-file-rename-ransomware.md`](sigma/T1486_mass-file-rename-ransomware.md)
