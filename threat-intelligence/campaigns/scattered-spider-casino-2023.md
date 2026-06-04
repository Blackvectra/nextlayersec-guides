# Campaign: Scattered Spider — 2023 Hospitality Sector Breaches

- **Period:** 2023-05 – 2023-12
- **Attributed to:** Scattered Spider (UNC3944 / Octo Tempest / Muddled Libra)
- **Last updated:** 2026-06-04

## Summary

Between May and December 2023, Scattered Spider executed a series of high-profile intrusions against North American hospitality and gaming companies, most publicly Caesars Entertainment and MGM Resorts International. Both organisations reported breaches in September 2023; Caesars paid approximately USD 15 million in ransom to prevent data publication, while MGM refused to pay and sustained an estimated USD 100 million in operational disruption and recovery costs. In both cases the actor entered through a help-desk social-engineering call lasting under 10 minutes, then pivoted from Okta to every connected SaaS and cloud control plane. At MGM, BlackCat/ALPHV ransomware was ultimately deployed against VMware ESXi hosts. The campaign is cited in CISA Advisory AA23-320A as a reference case for identity-centric, MFA-bypass-led intrusion.

**Other victims** (public reporting, same TTPs, same approximate window): multiple telecom carriers, a business-process outsourcer, and at least two managed-service providers — most undisclosed.

## Initial access

1. **LinkedIn / company-directory reconnaissance** — operator scraped the target's IT directory to identify a help-desk representative and an IT engineer whose identity they would impersonate.
2. **Vishing** — caller impersonated a named employee, claimed to be locked out, and convinced the help desk to reset the target's Okta MFA enrolment. The call at MGM reportedly lasted under 10 minutes. No phishing link was ever clicked.
3. **Legitimate sign-in as the employee** — with MFA re-enrolled on an attacker-controlled device, the actor authenticated legitimately to Okta admin and Microsoft Entra ID.

## Kill chain

1. **Recon** — LinkedIn scraping for help-desk staff and high-privilege employees; Maltego-style directory enumeration to build the pretext story (full name, title, manager chain). (T1591, T1589.002)
2. **Initial access** — vishing the IT help desk; MFA reset on a target account via Okta self-service admin; device registration of attacker-owned authenticator. (T1566, T1621, T1098.005)
3. **Execution** — access to Okta admin console → pivot to every Okta-integrated application; PowerShell / Azure CLI commands run from the compromised cloud session. (T1059.001, T1078.004)
4. **Persistence** — registered attacker device for passwordless sign-in; installed AnyDesk/ScreenConnect on endpoints discovered post-pivot; created back-door federated identity in Entra. (T1098.005, T1136, T1219)
5. **Privilege escalation** — Okta super-admin → Azure Global Admin role claim via Entra Connect sync; IAM privilege escalation in AWS where applicable. (T1078.004, T1484.002)
6. **Defense evasion** — inbox rules to forward / delete security-team email to victim's account; disabled EDR agents via legitimate admin tooling; deleted cloud audit logs where permissions allowed. (T1564.008, T1562.001)
7. **Credential access** — harvested secrets from SharePoint / Confluence pages (password vault URLs, service-account passwords, API keys); MFA fatigue push spam used in parallel as an alternate vector against accounts not reachable via help-desk pivot. (T1213.003, T1621, T1552.001)
8. **Discovery** — enumerated Entra groups, privileged roles, and device inventory; mapped AWS S3 buckets and Azure resource groups; identified VMware vCenter and ESXi hosts via Azure Arc and vSphere web client. (T1087.004, T1518, T1082)
9. **Lateral movement** — Entra → on-premises via Azure AD Connect server; Okta → connected SaaS (ServiceNow, Workday, Salesforce); RDP from cloud management host to on-prem servers. (T1021.007, T1021.001)
10. **Collection** — exfiltrated customer PII (loyalty programme data, partial payment card data, driver licence numbers, SSNs) — TBD — verify exact scope per victim; staged data in cloud storage prior to exfil. (T1530, T1074.002)
11. **C2** — ngrok and Cloudflare Tunnel used to proxy RMM traffic and maintain persistence without direct inbound exposure; Mega.nz for data staging and exfiltration. (T1572, T1567.002)
12. **Exfiltration** — multi-gigabyte archives uploaded to attacker-controlled Mega storage. (T1567.002)
13. **Impact** — at MGM: BlackCat/ALPHV ransomware deployed against ESXi hypervisors, encrypting VM images and causing widespread slot-machine, hotel check-in, and digital-key outages. At Caesars: extortion-only (ransom paid; no encryption confirmed publicly). (T1486, T1657)

## IOCs

> Most Scattered Spider IOCs rotate rapidly (domains registered hours before use; residential-proxy IPs). Treat the values below as illustrative; pull current indicators from the CISA advisory and threat-intel feeds before actioning.

- **Hashes:** TBD — verify; see CISA AA23-320A appendix and Mandiant UNC3944 indicator sets.
- **Domains / IPs:** Typo-squat patterns — `okta-<company>.com`, `sso-<company>.net`, `helpdesk-<company>.com`, `login-<company>-sso[.]com`; C2 via Cloudflare-tunnelled subdomains (`*.trycloudflare.com`); ngrok endpoints (`*.ngrok.io`, `*.ngrok-free.app`).
- **Filenames / paths:** `anydesk.exe`, `screenconnect.exe`, `rustdesk.exe`; ngrok binary renamed to common system names; PowerShell scripts matching `ADRecon*`, `AADInternals*`.

## Detections in this repo

- [`detections/kql/T1110.003_entra-password-spray.md`](../../detections/kql/T1110.003_entra-password-spray.md) — pre-pretext credential probing; often run against Entra before or alongside vishing.
- [`detections/kql/T1078.004_risky-signin-mailbox-rule.md`](../../detections/kql/T1078.004_risky-signin-mailbox-rule.md) — risky Entra sign-in followed by mailbox-rule creation; one of the earliest post-access signals.
- [`detections/kql/T1059.001_powershell-encoded-command.md`](../../detections/kql/T1059.001_powershell-encoded-command.md) — PowerShell-based discovery / lateral movement once inside.
- [`detections/kql/T1071.001_beaconing-rare-https.md`](../../detections/kql/T1071.001_beaconing-rare-https.md) — ngrok / Cloudflare tunnel C2 beacon pattern.
- [`detections/kql/T1486_mass-file-rename-ransomware.md`](../../detections/kql/T1486_mass-file-rename-ransomware.md) — ransomware encryption canary; triggered at MGM during BlackCat/ALPHV ESXi deployment.

## Related threat-intel in this repo

- Actor profile: [`threat-intelligence/actors/scattered-spider.md`](../actors/scattered-spider.md)
- TTP roundup: [`threat-intelligence/ttps/aitm-phishing-kits.md`](../ttps/aitm-phishing-kits.md) — AiTM kits are the technical complement to the vishing-based MFA reset used here.

## Defender guidance specific to this campaign pattern

- **Require callback verification (video or in-person) before any MFA reset** for accounts with Entra/Okta admin roles. Script a mandatory approval chain: the reset requires a manager's signed-off ticket, not just a verbal answer to security questions.
- **Alert on first-time Okta super-admin logins** from a new device or IP — especially outside business hours.
- **Restrict Entra Connect sync server access** to named admin workstations; alert on any interactive logon to the server outside a change window.
- **Block or alert on `*.trycloudflare.com` and `*.ngrok-free.app` DNS resolution** outside approved developer environments.
- **Monitor for new RMM binary drops** (AnyDesk, ScreenConnect, RustDesk) on servers and cloud management hosts.
- See the full actor-level guidance in the [Scattered Spider profile](../actors/scattered-spider.md).

## References

- CISA Joint Cybersecurity Advisory **AA23-320A — Scattered Spider** (November 2023): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a>
- Microsoft Threat Intelligence — **"Octo Tempest"** group profile and deep-dive (October 2023, updated 2024): search Microsoft Security Blog for "Octo Tempest".
- Mandiant / Google Cloud — **UNC3944** research series (multiple reports 2022–2025).
- Palo Alto Unit 42 — **"Muddled Libra"** (June 2023 initial publication; follow-up 2024).
- MGM Resorts 8-K filing (September 2023) — public disclosure of the incident and USD ~100 M financial impact estimate. **TBD — verify** final figure in the Q3 10-Q filing.
- Caesars Entertainment 8-K filing (September 2023) — confirms unauthorised actor obtained loyalty programme member data; ransom-payment amount (~USD 15 M) reported by Wall Street Journal and Bloomberg. **TBD — verify** confirmed amount vs. public reporting.
- NCSC (UK) — aligned advisory referencing Scattered Spider TTPs (cross-reference AA23-320A). **TBD — verify** specific NCSC publication number.
