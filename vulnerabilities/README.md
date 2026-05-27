# Vulnerabilities

Selective CVE library. Quality over quantity — prioritize:

1. **CISA KEV catalog** additions (actively exploited).
2. CVEs in commonly-deployed SOC scope: Fortinet, Cisco, Palo Alto, Microsoft Exchange / Sharepoint / Windows, Citrix, Ivanti, VMware, Atlassian, MOVEit, etc.
3. Anything with a **public PoC** or in-the-wild exploitation.

Each entry should include impact, detection guidance (link to a `detections/` rule when possible), mitigation, and framework mapping.

## Index

| CVE | Product | KEV | Detection | Notes file |
|-----|---------|-----|-----------|------------|
| CVE-2025-50154 | _see file_ | ? | _todo_ | [CVE-2025-50154.md](CVE-2025-50154.md) |

Use [`template.md`](template.md) when adding a new CVE.
