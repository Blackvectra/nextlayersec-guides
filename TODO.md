# TODO

Backlog ordered by realistic ship value. Grab a top item from a section, write it, PR it, tick it off. Done items are kept (with links) so the file doubles as a shipped-work log.

> The scheduled reminder workflows under `.github/workflows/` (`daily-reminder`, `discord-reminder`, `daily-draft`) are **disabled on schedule** — they only run via manual dispatch from the Actions tab. This file is the source of truth; no auto-pings.

---

## 🔥 Next up (highest leverage)

These are the smallest things that materially improve the repo.

- [ ] **Ransomware-outbreak playbook** — pairs with the existing T1486 detection; biggest content gap in `blue-team-playbooks/`.
- [ ] **Detection: T1071.001 — beacon-like outbound HTTPS to rare destination** — fills the Command & Control tactic gap (currently 0 in COVERAGE).
- [ ] **Detection: T1078.004 — Entra risky sign-in followed by mailbox rule creation** — direct Scattered Spider TTP follow-up.
- [ ] **YARA syntax check in CI** — finishes the "Sigma+YARA validation" item; small workflow addition.
- [ ] **First TTP roundup** — AiTM phishing kits or MFA fatigue. Both tie back to Scattered Spider.

---

## Playbooks

Priority order — top is highest demand for SOC readers.

- [x] Phishing email triage — [`blue-team-playbooks/phishing-email-triage.md`](blue-team-playbooks/phishing-email-triage.md)
- [ ] Ransomware outbreak
- [ ] Credential theft / password spray
- [ ] Cloud account compromise (Entra ID / AWS / GCP)
- [ ] Business email compromise (BEC)
- [ ] Lateral movement (RDP / SMB / WMI)
- [ ] Malware infection (endpoint)
- [ ] Data exfiltration
- [ ] Insider threat
- [ ] DDoS

## Detection workflows

- [ ] Suspicious sign-in (impossible travel / risky IP)
- [ ] Beaconing / C2 traffic
- [ ] LOLBin abuse (rundll32, mshta, regsvr32)
- [ ] Office macro execution
- [ ] Phishing email triage (workflow, distinct from the playbook)
- [ ] Suspicious scheduled task / service install

## Detections (KQL + Sigma)

Format: `T<id> — name — [KQL] · [Sigma]`. Tick when both ship.

- [x] T1003.001 — LSASS access by non-system process — [KQL](detections/kql/T1003.001_lsass-access-suspicious.md) · [Sigma](detections/sigma/T1003.001_lsass-access-suspicious.md)
- [x] T1059.001 — PowerShell encoded command — [KQL](detections/kql/T1059.001_powershell-encoded-command.md) · [Sigma](detections/sigma/T1059.001_powershell-encoded-command.md)
- [x] T1110.003 — Entra password spray — [KQL](detections/kql/T1110.003_entra-password-spray.md) · [Sigma](detections/sigma/T1110.003_entra-password-spray.md)
- [x] T1486 — Mass file rename (ransomware canary) — [KQL](detections/kql/T1486_mass-file-rename-ransomware.md) · [Sigma](detections/sigma/T1486_mass-file-rename-ransomware.md)
- [x] T1547.001 — Run / RunOnce key persistence — [KQL](detections/kql/T1547.001_runkey-persistence.md) · [Sigma](detections/sigma/T1547.001_runkey-persistence.md)
- [ ] T1071.001 — Beacon-like outbound HTTPS to rare destination
- [ ] T1078.004 — Entra risky sign-in + mailbox-rule creation
- [ ] T1218.011 — rundll32 with unusual command line
- [ ] T1021.001 — RDP from unusual source
- [ ] T1053.005 — Scheduled task created by non-installer
- [ ] T1543.003 — Windows service installed from user-writable path

## CVEs to write up

- [ ] One from the current [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) per session
- [ ] Backfill any CVE referenced by playbooks / detections
- [x] CVE-2025-50154 (NTLM disclosure in Explorer) — [`vulnerabilities/CVE-2025-50154.md`](vulnerabilities/CVE-2025-50154.md)

## Threat intel

- [x] First actor profile — [Scattered Spider](threat-intelligence/actors/scattered-spider.md)
- [ ] Second actor profile (suggestion: Lazarus / Konni / FIN7 — pick one your environment is realistically exposed to)
- [ ] First campaign write-up
- [ ] First TTP roundup — candidates: AiTM phishing kits, OAuth consent phishing, AS-REP roasting, MFA fatigue

## Purple-team labs

- [ ] T1059.001 — Atomic Red Team encoded PowerShell tests vs. the KQL rule
- [ ] T1547.001 — Atomic Red Team Run-key tests vs. the new detection
- [ ] T1078 — Entra valid-accounts
- [ ] T1021.001 — RDP lateral movement
- [ ] T1055 — process injection

## Repo hygiene & infrastructure

- [x] `LICENSE` (MIT)
- [x] `SECURITY.md`
- [x] `CODEOWNERS`
- [x] `.github/dependabot.yml`
- [x] PR + issue templates
- [x] `COVERAGE.md` (MITRE ATT&CK matrix)
- [x] `detections/DATA_SOURCES.md`
- [x] Markdown + link CI
- [x] Sigma validation CI (pysigma)
- [ ] YARA validation CI
- [ ] Spell check (typos) CI
- [ ] `CODE_OF_CONDUCT.md`
- [ ] Badges on root README (CI status, license, last release)
- [ ] Per-backend "how to deploy" guides (Sentinel analytic rule / Defender custom detection / Splunk savedsearches.conf)

## Automation (reminders)

These exist but their schedules are commented out — they run manual-only.

- [x] `daily-reminder.yml` — opens a GitHub issue with the day's lane
- [x] `discord-reminder.yml` — Tier 2 Discord ping with live CISA KEV data on Mondays
- [x] `daily-draft.yml` — Tier 3 agentic drafting (Mon CVE, Tue detection)
- [ ] If/when you want auto-reminders again, uncomment the `schedule:` block in each file.
