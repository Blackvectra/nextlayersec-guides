# KQL Detections

Kusto Query Language (KQL) detections for Microsoft Sentinel, Defender XDR, and Log Analytics.

## File pairing

Each detection ships as two files with the same basename:

- `<name>.kql` — the query itself, runnable as-is
- `<name>.md` — context, data sources, ATT&CK mapping, FP notes, tuning

## Template

See [`_template.md`](_template.md) and [`_template.kql`](_template.kql).

## Index

| Technique | File | Status | Description |
|-----------|------|--------|-------------|
| T1003.001 | [`T1003.001_lsass-access-suspicious`](T1003.001_lsass-access-suspicious.md) | testing | Non-Microsoft process opens LSASS with credential-dump-capable rights |
| T1566.001 | [`T1566.001_attachment-link-credential-harvester`](T1566.001_attachment-link-credential-harvester.md) | testing | Delivered inbound mail: attachment + link to credential harvester on abused free hosting + weak auth |
| T1059.001 | [`T1059.001_powershell-encoded-command`](T1059.001_powershell-encoded-command.md) | testing | PowerShell `-EncodedCommand` / `FromBase64String` |
| T1110.003 | [`T1110.003_entra-password-spray`](T1110.003_entra-password-spray.md) | testing | Single IP fails sign-ins against many Entra users |
| T1486 | [`T1486_mass-file-rename-ransomware`](T1486_mass-file-rename-ransomware.md) | testing | Process renames many files across directories — ransomware canary |
| T1547.001 | [`T1547.001_runkey-persistence`](T1547.001_runkey-persistence.md) | testing | Non-installer process writes a Run / RunOnce / Winlogon autostart value |
| T1071.001 | [`T1071.001_beaconing-rare-https`](T1071.001_beaconing-rare-https.md) | testing | Workstation makes sustained outbound HTTPS to a fleet-rare destination (C2 beacon) |
