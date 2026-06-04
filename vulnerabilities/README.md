# Vulnerabilities

Selective CVE library. Quality over quantity. Selection priority (top is most relevant to this repo's target environment — Windows-heavy MSP / SOC fleets):

1. **Microsoft Windows ecosystem** — Windows client/server, Active Directory, Entra ID, Exchange, SharePoint, Office / M365, Defender, Intune, Windows Server roles.
2. **Edge / identity / virtualization gear deployed alongside Windows fleets** — Fortinet, Cisco ASA / IOS XE / Firepower, Palo Alto PAN-OS, Citrix ADC / NetScaler, Ivanti Connect Secure / EPM, VMware vCenter / ESXi, F5 BIG-IP, Atlassian, MOVEit, ConnectWise, Veeam, Kaseya, SolarWinds.
3. **Anything with a public PoC or in-the-wild exploitation**, especially CISA KEV catalog additions.
4. Other CVEs only when 1–3 have nothing fresh.

Within those buckets, prefer CISA KEV entries, then anything actively exploited per vendor or government advisory.

Each entry must include impact, detection guidance (link to a `detections/` rule when possible), mitigation, framework mapping, and primary-source citations.

## Index

| CVE | Product | KEV | Detection | Notes file |
|-----|---------|-----|-----------|------------|
| CVE-2025-50154 | _see file_ | ? | _todo_ | [CVE-2025-50154.md](CVE-2025-50154.md) |
| CVE-2022-0492 | Linux Kernel (cgroups v1) | Yes (added 2026-06-02) | host-side file_event on `**/release_agent` writes; Falco built-in rule | [CVE-2022-0492.md](CVE-2022-0492.md) |

Use [`template.md`](template.md) when adding a new CVE.
