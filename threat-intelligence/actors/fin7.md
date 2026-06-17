# Actor: FIN7

A financially-motivated cybercrime group active since at least 2015. One of the most prolific and consistently profitable e-crime crews, with documented activity across retail, hospitality, restaurant, healthcare, manufacturing, and managed-service-provider verticals. FIN7's tradecraft has evolved through multiple phases — point-of-sale memory-scraping (2015-2018), business-email-compromise + macro phishing (2018-2020), Cobalt Strike + ransomware affiliate roles (2020+), to custom loader development and ransomware affiliation with multiple brands (BlackBasta, Black Cat / ALPHV, Royal, Maze, REvil) in recent years.

- **Author:** nextlayersec
- **Last updated:** 2026-06-08
- **TLP:** White

## Aliases

- **FIN7** (Mandiant naming)
- **Carbanak Group** (some early reporting; technically Carbanak was an overlapping intrusion set targeting financial institutions; the two groups share tooling and have been grouped in some reports)
- **Carbon Spider** (CrowdStrike)
- **Sangria Tempest** (Microsoft, current naming convention)
- **GOLD NIAGARA** (SecureWorks)
- **ITG14** (IBM X-Force)

## Origin and motivation

- **Motivation:** financial, full stop. FIN7 has not been linked to state-aligned objectives or espionage tasking.
- **Origin:** Russian-speaking individuals. Multiple alleged members have been indicted in U.S. federal courts (2018-2023), including senior leadership; the group has continued to operate after each indictment, suggesting a deeper bench.
- **Business model:** historically operated as a centralized crew with a front company ("Combi Security") that recruited unwitting penetration testers. Currently functions as both a direct intrusion crew AND an affiliate of multiple ransomware-as-a-service brands.

## Targets

| Vertical | Why |
|---|---|
| **Retail / hospitality / restaurant** | Original POS-skimming focus; many returning targets in recurring campaigns. |
| **Healthcare** | Mid-2020+ — ransomware-friendly pressure: stolen data + downtime threats. |
| **Manufacturing** | Same — operational downtime gives ransomware significant leverage. |
| **Managed Service Providers (MSPs)** | High-leverage target: one MSP compromise = multiple downstream tenants. **Directly relevant to NextLayerSec.** |
| **Software / IT consulting** | Supply-chain access; FIN7 has used legitimate vendor relationships to land. |

The MSP-targeting pattern is the operational concern for any MSP reading this profile. FIN7 has historically used:

- Trojanized "secure file" submissions to MSP support inboxes.
- Job-application phishing targeting MSP recruiters with a malicious "résumé" attachment.
- Fake software-vendor outreach offering "evaluation" packages with malicious installers.
- Direct supply-chain attacks against tools the MSP deploys to clients.

## Tradecraft and tooling

### Initial access

- **Spearphishing with malicious documents** — historically Word + Excel macros; recently SVG + LNK + ISO + IMG containers to bypass mark-of-the-web prompts. The "submission of important documents" template (fake government inquiry, fake court summons) is signature.
- **Trojanized installers** — fake updates for legitimate software (Adobe, Microsoft Teams, Google Chrome) hosted on lookalike domains.
- **Social-engineering phone calls** — "your finance department needs to verify this invoice" / "your tech support is calling about a malware infection" patterns.
- **External Remote Services** — opportunistic exploitation of internet-exposed RDP, VPN, and management interfaces.

### Execution and persistence

- **PowerShell** with heavy obfuscation — encoded commands, AMSI bypass, in-memory load of subsequent stages. Pairs with the [`T1059.001 PowerShell-encoded-command detection`](../../detections/kql/T1059.001_powershell-encoded-command.md).
- **JavaScript / WScript / MSHTA** — second-stage execution from documents.
- **Registry Run keys** — common persistence for the loader stage. Pairs with [`T1547.001 RunKey persistence`](../../detections/kql/T1547.001_runkey-persistence.md).
- **Scheduled tasks** — second persistence layer.
- **Custom backdoors** — historically Carbanak, GRIFFON, BABYMETAL, more recently DICELOADER / Lizar / POWERTRASH.

### Lateral movement

- **Stolen credentials** from harvested KeePass / browser stores / Mimikatz-extracted LSASS dumps.
- **RDP** with stolen creds — pairs with [`T1021.001 RDP-from-unusual-source detection`](../../detections/kql/T1021.001_rdp-unusual-source.md).
- **PSExec / WMI / SMB** for in-domain lateral movement.
- **Cobalt Strike** for command and control, with custom Malleable C2 profiles to evade network detection.

### Credential access

- **LSASS dumping** — Mimikatz, ProcDump, comsvcs.dll, custom tooling. Pairs with [`T1003.001 LSASS-access-suspicious detection`](../../detections/kql/T1003.001_lsass-access-suspicious.md).
- **DPAPI abuse** — extraction of saved credentials from browsers and password managers.
- **Kerberoasting** — opportunistic against weak SPN-bound service accounts.

### Defense evasion

- **AMSI / ETW bypasses** in PowerShell stages.
- **DLL side-loading** with legitimate signed binaries (rundll32, regsvr32, mshta, msbuild). Pairs with [`T1218.011 Rundll32-unusual-command-line detection`](../../detections/kql/T1218.011_rundll32-unusual-cmdline.md).
- **Driver-level rootkits** in some recent campaigns (BYOVD — bring-your-own-vulnerable-driver pattern).

### Impact

- **Ransomware deployment** as a final stage. FIN7 has functioned as an **affiliate** of multiple ransomware brands rather than running its own consistently — including BlackBasta, ALPHV/BlackCat, Royal, Maze (historical), and others. The financial model shifted from POS-skimming + transaction fraud (low per-victim revenue, high volume) to ransomware + extortion (high per-victim revenue, lower volume).
- **Data exfiltration** before encryption — used as leverage for double-extortion. Pairs with the [`T1486 Mass file rename detection`](../../detections/kql/T1486_mass-file-rename-ransomware.md) as the late-stage signal.

## Defensive priorities

For a Windows-MSP defender, FIN7-aligned defensive priorities (in order):

1. **Phishing-resistant MFA** on all admin accounts. FIN7 has demonstrated AiTM kit usage and credential harvesting; phone-call / TOTP MFA is bypassed by both. Hardware-key FIDO2 / Windows Hello for Business is the floor.
2. **Macro + ISO + IMG + LNK execution lockdown.** Defender for Endpoint ASR rules block-mode for "Block Office applications from creating child processes", "Block Win32 API calls from Office macros", "Block executable content from email client and webmail". Smart App Control / WDAC for hardened endpoints.
3. **EDR with tamper protection** on every endpoint. FIN7 specifically targets EDR uninstall + bypass.
4. **LSASS protection** (Credential Guard, LSA PPL). FIN7 historically dumps LSASS as the primary credential-harvest step.
5. **External Remote Services hygiene** — no internet-exposed RDP, IPS / firewall rules on every VPN / management interface, MFA on every remote-access portal.
6. **Network egress filtering** — Cobalt Strike with Malleable C2 still has to talk to the internet. Block outbound to non-business destinations from servers and admin tier endpoints.
7. **Offline-immutable backups** — Veeam / Backblaze / Wasabi with object-lock; rotation; periodic restore tests. FIN7-affiliated ransomware will go after backups before encryption.
8. **MSP-specific controls** — segregated admin tenants per client, no shared credentials, no shared service accounts. The compromise of one client tenant must not enable lateral movement into another.

## Indicators of campaign-level activity (hunt patterns)

When triaging an incident on a Windows-fleet client and suspecting FIN7-aligned tradecraft:

- **Cobalt Strike named-pipe pattern** in `DeviceProcessEvents` — process creates a `\\.\pipe\msagent_*`, `\\.\pipe\status_*`, `\\.\pipe\MSSE-*` pipe matching common CS profiles.
- **PowerShell with AMSI bypass attempts** — `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` patterns in `ScriptBlockLogging`.
- **rundll32 / regsvr32 / mshta abuse** with unsigned DLLs from `\AppData\`, `\Temp\`, `\Public\` — pairs with the T1218.011 detection.
- **LSASS access from non-Microsoft processes** with `0x1010` or `0x1400` access rights — the T1003.001 detection.
- **Mailbox forwarding rules** added by accounts that don't normally use them, especially from external IPs — the T1078.004 detection.

## References

- CISA / FBI joint advisory on FIN7 / Carbanak (multiple advisories, 2018-2024): search CISA.gov for "FIN7".
- Mandiant FIN7 tracking notes (multiple blogs): <https://cloud.google.com/blog>.
- Microsoft Threat Intelligence — Sangria Tempest: search Microsoft Security Blog for "Sangria Tempest".
- CrowdStrike — Carbon Spider profile: <https://www.crowdstrike.com/adversaries/>.
- SecureWorks — GOLD NIAGARA: search SecureWorks for "GOLD NIAGARA".
- Public indictments: U.S. DOJ announcements 2018, 2023 — search "FIN7 indictment".

## Related repo content

- **Threat-intel TTP:** [`Adversary-in-the-Middle phishing kits`](../ttps/aitm-phishing-kits.md) — the kit family FIN7 has used.
- **Threat-intel actor:** [`Scattered Spider`](scattered-spider.md) — different motivation (extortion) but similar Windows-fleet TTPs.
- **Detection:** [`T1003.001 LSASS access`](../../detections/kql/T1003.001_lsass-access-suspicious.md), [`T1059.001 PowerShell encoded`](../../detections/kql/T1059.001_powershell-encoded-command.md), [`T1218.011 Rundll32 unusual`](../../detections/kql/T1218.011_rundll32-unusual-cmdline.md), [`T1547.001 Run-key persistence`](../../detections/kql/T1547.001_runkey-persistence.md), [`T1486 Mass file rename`](../../detections/kql/T1486_mass-file-rename-ransomware.md).
- **Playbook:** [`Credential theft / password spray`](../../blue-team-playbooks/credential-theft-password-spray.md), [`Ransomware outbreak`](../../blue-team-playbooks/ransomware-outbreak.md).
- **Hardening:** [`Windows endpoint baseline`](../../hardening/windows-endpoint.md), [`Entra ID Conditional Access`](../../hardening/entra-id.md).
