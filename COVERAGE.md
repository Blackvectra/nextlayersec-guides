# MITRE ATT&CK Coverage

A live map of which ATT&CK techniques this repo covers and at what depth.

## Legend

- 🛡 **Detection** — a rule exists in `detections/`
- 📕 **Playbook** — an IR playbook exists in `blue-team-playbooks/`
- 🔍 **Workflow** — a triage workflow exists in `detection-workflows/`
- 🧪 **Lab** — a purple-team lab exists in `purple-team-labs/`

A row appears only when this repo covers the technique. Pull requests adding coverage should update this file in the same PR.

## Coverage table

| Tactic | Technique | Sub-technique | 🛡 | 📕 | 🔍 | 🧪 |
|--------|-----------|---------------|----|----|----|----|
| Initial Access | T1566 Phishing | — | | [phishing-email-triage](blue-team-playbooks/phishing-email-triage.md) | | |
| Initial Access | T1566.001 Spearphishing Attachment | | | [phishing-email-triage](blue-team-playbooks/phishing-email-triage.md) | | |
| Initial Access | T1566.002 Spearphishing Link | | | [phishing-email-triage](blue-team-playbooks/phishing-email-triage.md) | | |
| Execution | T1059.001 PowerShell | | [KQL](detections/kql/T1059.001_powershell-encoded-command.md) | | [PowerShell attacks](detection-workflows/detection-workflow-powershell-attacks.md) | |
| Credential Access | T1003.001 LSASS Memory | | [KQL](detections/kql/T1003.001_lsass-access-suspicious.md) | | | |
| Credential Access | T1110.003 Password Spraying | | [KQL](detections/kql/T1110.003_entra-password-spray.md) | | | |
| Defense Evasion / Persistence | _various_ | | | [incident-response-suspicious-network](blue-team-playbooks/incident-response-suspicious-network.md) | | |
| Impact | T1486 Data Encrypted for Impact | | [KQL](detections/kql/T1486_mass-file-rename-ransomware.md) | | | |

## Headline coverage by tactic

| Tactic | Detections | Playbooks | Workflows | Labs |
|--------|------------|-----------|-----------|------|
| Reconnaissance (TA0043) | 0 | 0 | 0 | 0 |
| Resource Development (TA0042) | 0 | 0 | 0 | 0 |
| Initial Access (TA0001) | 0 | 1 | 0 | 0 |
| Execution (TA0002) | 1 | 0 | 1 | 0 |
| Persistence (TA0003) | 0 | 0 | 0 | 0 |
| Privilege Escalation (TA0004) | 0 | 0 | 0 | 0 |
| Defense Evasion (TA0005) | 0 | 0 | 0 | 0 |
| Credential Access (TA0006) | 2 | 0 | 0 | 0 |
| Discovery (TA0007) | 0 | 0 | 0 | 0 |
| Lateral Movement (TA0008) | 0 | 0 | 0 | 0 |
| Collection (TA0009) | 0 | 0 | 0 | 0 |
| Command & Control (TA0011) | 0 | 0 | 0 | 0 |
| Exfiltration (TA0010) | 0 | 0 | 0 | 0 |
| Impact (TA0040) | 1 | 0 | 0 | 0 |

## Priority gaps

Tactics with **zero** coverage and high SOC relevance — pick these first when planning new content:

1. **Persistence** — T1547.001 Run keys, T1053.005 Scheduled task, T1543.003 Windows service.
2. **Lateral Movement** — T1021.001 RDP, T1021.002 SMB/Admin shares.
3. **Command & Control** — T1071.001 Web protocols, T1572 Protocol tunneling.
4. **Exfiltration** — T1567 Web service, T1041 C2 channel exfil.
5. **Defense Evasion** — T1218 System binary proxy execution (LOLBins).

## Export to ATT&CK Navigator

Once coverage grows past ~15 techniques, generate a Navigator JSON layer and link it here. Suggested filename: `attack-navigator-layer.json` at repo root. The script and instructions can be added under `tools/` when needed.
