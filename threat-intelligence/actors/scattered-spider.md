# Actor: Scattered Spider

- **Aliases:** UNC3944, Octo Tempest (Microsoft), Muddled Libra (Palo Alto Unit 42), 0ktapus, Scatter Swine, Roasted 0ktapus, Storm-0875
- **Suspected origin:** primarily English-speaking; reporting points to members in the US, UK, and Canada (loosely affiliated, sometimes operating under "The Com")
- **Motivation:** financial (SIM swap → fraud → extortion / ransomware affiliate)
- **Active since:** 2022 (publicly named); related activity tracked earlier
- **Last updated:** 2026-05-28

## Summary

Scattered Spider is a financially motivated, English-speaking intrusion set known for **identity-centric** attacks: high-quality social engineering against IT help desks, SMS / push-notification MFA bombing, SIM swapping, and rapid movement into SaaS and cloud control planes (Okta, Entra ID / Azure AD, Microsoft 365, AWS, Snowflake, VMware vSphere). Since 2023 the group has been an affiliate of multiple ransomware operations (BlackCat / ALPHV, RansomHub, Qilin) and has hit hospitality, telecoms, retail, financial services, gaming, BPOs, and managed-service providers.

## Targeting

- **Sectors:** telecom, hospitality, retail, financial services, gaming / casinos, business process outsourcing (BPO), MSPs/MSSPs, healthcare.
- **Regions:** primarily North America and Western Europe; English-language environments preferred (matches their pretexting strength).
- **Notable victims (public reporting):** MGM Resorts (2023), Caesars Entertainment (2023), multiple BPOs and telecom carriers (2022–2024), various large enterprises via Snowflake / Okta abuse (2024–2025).

## TTPs (MITRE ATT&CK)

| Tactic | Technique | Notes |
|--------|-----------|-------|
| Reconnaissance | T1591 Gather Victim Org Information | LinkedIn / company directory scraping to identify help-desk targets and victim names. |
| Resource Development | T1583.001 Acquire Infrastructure: Domains | Typo-squat domains imitating `okta`, `sso`, IT support portals; commonly registered hours before use. |
| Initial Access | T1566 Phishing — voice (vishing) and SMS (smishing) | Calls the help desk impersonating an employee; texts targets with fake SSO pages. |
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | Help-desk-driven MFA reset → legitimate sign-in. |
| Credential Access | T1621 Multi-Factor Authentication Request Generation | "MFA fatigue" — repeated push spam until the user approves. |
| Credential Access | T1110.003 Password Spraying | Common pre-pretext step against tenant sign-in endpoints. |
| Credential Access | T1556.006 Multi-Factor Authentication | Convince help desk to disable / re-enroll MFA on the target account. |
| Persistence | T1098.005 Account Manipulation: Device Registration | Register attacker-controlled device for passwordless / MFA. |
| Persistence | T1136 Create Account | Create new federated identities, IAM users, or RMM tenants. |
| Defense Evasion | T1564.008 Email Hiding Rules | Inbox rules to hide IT / security replies during pretexting. |
| Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | Disable EDR via legitimate admin tooling; delete logs in cloud. |
| Lateral Movement | T1021.007 Cloud Services | Pivot from Entra to Azure, then to on-prem via Azure AD Connect; abuse Okta admin to reach connected SaaS. |
| Lateral Movement | T1219 Remote Access Software | Install AnyDesk / ScreenConnect / TeamViewer / Splashtop / RustDesk on hosts. |
| Discovery | T1087.004 Account Discovery: Cloud Account | Enumerate admins, groups, and privileged roles in Entra / Okta / AWS IAM. |
| Collection | T1213.003 Data from Information Repositories: Code Repositories | Scrape SharePoint, Confluence, GitHub, and ticket systems for secrets. |
| Exfiltration | T1567 Exfiltration Over Web Service | Mega, Dropbox, S3, sometimes attacker-controlled WebDAV. |
| Impact | T1486 Data Encrypted for Impact | Deploys partner-RaaS payloads (BlackCat/ALPHV, RansomHub, Qilin) on the way out. |
| Impact | T1657 Financial Theft | SIM-swap-enabled bank fraud and cryptocurrency theft outside ransomware operations. |

## Tooling

- **Remote management / RMM:** AnyDesk, ScreenConnect, TeamViewer, Splashtop, RustDesk, Pulseway, Atera, Action1.
- **Tunnelling / pivoting:** ngrok, Cloudflared tunnels, plink, Chisel.
- **Credential / token theft:** Mimikatz, ADRecon, raw browser-token theft, custom Okta session-token replay.
- **Phishing kits:** evilginx / muraena-style adversary-in-the-middle kits hosting `okta-*.com`-style domains.
- **Ransomware (as affiliate):** BlackCat / ALPHV (until 2024), RansomHub (2024–), Qilin, occasional INC.
- **LOLBins / built-ins:** `net.exe`, `nltest`, `whoami /priv`, `quser`, PowerShell modules (ADModule, MSOnline, AzureAD/Microsoft.Graph), Azure CLI, AWS CLI.

## Detections in this repo

- [`detections/kql/T1110.003_entra-password-spray.kql`](../../detections/kql/T1110.003_entra-password-spray.md) — pre-pretext credential probing.
- [`detections/kql/T1059.001_powershell-encoded-command.kql`](../../detections/kql/T1059.001_powershell-encoded-command.md) — common post-access discovery / collection.
- [`detections/kql/T1003.001_lsass-access-suspicious.kql`](../../detections/kql/T1003.001_lsass-access-suspicious.md) — on-host credential dumping when Scattered Spider drops to endpoint.

## Defender guidance

- **Phishing-resistant MFA only** for admins and high-value users — FIDO2 / certificate-based / Windows Hello for Business. Disable SMS, voice, and weakened-push as MFA methods.
- **Lock down help-desk processes**: require a second factor (callback to a manager, video verification, in-person check) before resetting MFA or passwords for anyone with privileged roles. Audit the process quarterly with a tabletop.
- **Restrict device registration** in Entra ID to enrolled / compliant devices; alert on first-time registrations for privileged accounts (see [`T1098.005`](https://attack.mitre.org/techniques/T1098/005/)).
- **Monitor for new RMM installs** — alert on first-seen `anydesk.exe`, `screenconnect.exe`, `teamviewer.exe`, `rustdesk.exe`, `splashtop*.exe` outside approved admin hosts.
- **Privileged Identity Management (PIM)** with just-in-time approvals for Global Admin, Application Admin, Cloud Application Admin, Helpdesk Admin.
- **Token-binding / continuous access evaluation (CAE)** in Entra to shrink the window after a token theft.
- **Egress allow-listing** for cloud-admin actions — restrict Azure CLI / AWS CLI calls from corporate networks or named locations only.
- **Snowflake / SaaS specifics** — enforce MFA on every account, IP-restrict service accounts, monitor for new programmatic-access tokens.

## References

- CISA Joint Cybersecurity Advisory **AA23-320A — Scattered Spider** (November 2023): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
- CISA / FBI / NSA Joint Advisory updates on Scattered Spider (2024 updates).
- Microsoft Threat Intelligence — "Octo Tempest" deep-dive (October 2023 onward).
- Mandiant / Google Cloud reporting on UNC3944.
- Palo Alto Unit 42 — "Muddled Libra" series.
- MITRE ATT&CK group page for Scattered Spider (technique mappings).
