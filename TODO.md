# TODO

Working backlog. **Sections marked `<!-- BEGIN AUTO: ... -->` are regenerated automatically** by `scripts/sync-todo.py` from what's actually on disk, so once a file lands the matching item ticks itself. Hand-edits to those blocks will be overwritten on the next sync; manual notes belong in the un-marked sections below.

The sync runs:

- On every push to `main` (via `.github/workflows/todo-sync.yml`).
- Locally: `python scripts/sync-todo.py` — re-run after creating or moving content.
- In PR CI as `--check`: a PR that adds files without re-running the sync will fail until you do.

---

## 📊 Status (auto)

<!-- BEGIN AUTO: summary -->

| Area | Shipped |
|---|---|
| Detections (techniques covered) | 7 |
| Playbooks | 3 |
| Detection workflows | 1 |
| CVE write-ups | 2 |
| Threat actors profiled | 1 |
| Threat-intel campaigns | 0 |
| Threat-intel TTP roundups | 1 |
| Purple-team labs | 0 |

<!-- END AUTO: summary -->

---

## 🔥 Next up (manual — order by what you want to ship)

These are the highest-leverage items not yet shipped. Re-order as priorities shift.

- [ ] **Ransomware-outbreak playbook** — pairs with the existing T1486 detection; biggest content gap.
- [ ] **Detection: T1071.001 — beacon-like outbound HTTPS to rare destination** — fills the C2 tactic gap.
- [ ] **Detection: T1078.004 — Entra risky sign-in + mailbox-rule creation** — direct Scattered Spider follow-up.
- [ ] **YARA syntax check in CI** — finishes the Sigma+YARA validation item.
- [ ] **First TTP roundup** — AiTM phishing kits or MFA fatigue.

---

## Detections (auto)

<!-- BEGIN AUTO: detections -->

| Tech ID | Title | KQL | Sigma |
|---|---|:---:|:---:|
| `T1003.001` | Suspicious LSASS Process Access (Sigma) | [✅](detections/kql/T1003.001_lsass-access-suspicious.md) | [✅](detections/sigma/T1003.001_lsass-access-suspicious.md) |
| `T1059.001` | PowerShell Encoded Command Execution (Sigma) | [✅](detections/kql/T1059.001_powershell-encoded-command.md) | [✅](detections/sigma/T1059.001_powershell-encoded-command.md) |
| `T1071.001` | Beacon-like Outbound HTTPS to Rare Destination (Sigma) | [✅](detections/kql/T1071.001_beaconing-rare-https.md) | [✅](detections/sigma/T1071.001_beaconing-rare-https.md) |
| `T1078.004` | Risky Entra sign-in followed by mailbox-rule mutation (Sigma) | [✅](detections/kql/T1078.004_risky-signin-mailbox-rule.md) | [✅](detections/sigma/T1078.004_risky-signin-mailbox-rule.md) |
| `T1110.003` | Entra ID Password Spray (Sigma) | [✅](detections/kql/T1110.003_entra-password-spray.md) | [✅](detections/sigma/T1110.003_entra-password-spray.md) |
| `T1486` | Mass File Rename — Ransomware Encryption Canary (Sigma) | [✅](detections/kql/T1486_mass-file-rename-ransomware.md) | [✅](detections/sigma/T1486_mass-file-rename-ransomware.md) |
| `T1547.001` | Run / RunOnce Key Persistence by Non-Installer | [✅](detections/kql/T1547.001_runkey-persistence.md) | [✅](detections/sigma/T1547.001_runkey-persistence.md) |

<!-- END AUTO: detections -->

### Detection backlog (manual)

Techniques worth covering next; tick automatically once a `.kql` or `.yml` lands.

- [ ] T1071.001 — Beacon-like outbound HTTPS to rare destination
- [ ] T1078.004 — Entra risky sign-in + mailbox-rule creation
- [ ] T1218.011 — rundll32 with unusual command line
- [ ] T1021.001 — RDP from unusual source
- [ ] T1053.005 — Scheduled task created by non-installer
- [ ] T1543.003 — Windows service installed from user-writable path

---

## Playbooks

### Shipped (auto)

<!-- BEGIN AUTO: playbooks -->

- [x] [Incident Response Playbook: Suspicious Network Activity](blue-team-playbooks/incident-response-suspicious-network.md)
- [x] [Playbook: Phishing Email Triage](blue-team-playbooks/phishing-email-triage.md)
- [x] [Playbook: Ransomware Outbreak](blue-team-playbooks/ransomware-outbreak.md)

<!-- END AUTO: playbooks -->

### Backlog (manual)

Priority order — top is highest demand for SOC readers.

- [ ] Ransomware outbreak
- [ ] Credential theft / password spray
- [ ] Cloud account compromise (Entra ID / AWS / GCP)
- [ ] Business email compromise (BEC)
- [ ] Lateral movement (RDP / SMB / WMI)
- [ ] Malware infection (endpoint)
- [ ] Data exfiltration
- [ ] Insider threat
- [ ] DDoS

---

## Detection workflows

### Shipped (auto)

<!-- BEGIN AUTO: detection-workflows -->

- [x] [Detection Workflow: PowerShell-based Attacks](detection-workflows/detection-workflow-powershell-attacks.md)

<!-- END AUTO: detection-workflows -->

### Backlog (manual)

- [ ] Suspicious sign-in (impossible travel / risky IP)
- [ ] Beaconing / C2 traffic
- [ ] LOLBin abuse (rundll32, mshta, regsvr32)
- [ ] Office macro execution
- [ ] Phishing email triage (workflow form)
- [ ] Suspicious scheduled task / service install

---

## CVE write-ups

### Shipped (auto)

<!-- BEGIN AUTO: cves -->

- [x] [CVE-2022-0492 — Linux Kernel cgroups v1 `release_agent` Container Escape](vulnerabilities/CVE-2022-0492.md)
- [x] [CVE-2025-50154 Remediation](vulnerabilities/CVE-2025-50154.md)

<!-- END AUTO: cves -->

### Backlog (manual)

- [ ] One fresh entry per Monday from the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [ ] Backfill any CVE referenced by playbooks / detections

---

## Threat intel

### Actors profiled (auto)

<!-- BEGIN AUTO: actors -->

- [x] [Actor: Scattered Spider](threat-intelligence/actors/scattered-spider.md)

<!-- END AUTO: actors -->

### Campaigns (auto)

<!-- BEGIN AUTO: campaigns -->

_No campaign write-ups shipped yet._

<!-- END AUTO: campaigns -->

### TTP roundups (auto)

<!-- BEGIN AUTO: ttps -->

- [x] [TTP roundup: Adversary-in-the-Middle (AiTM) phishing kits](threat-intelligence/ttps/aitm-phishing-kits.md)

<!-- END AUTO: ttps -->

### Backlog (manual)

- [ ] Second actor profile (suggestion: Lazarus / Konni / FIN7)
- [ ] First campaign write-up
- [ ] First TTP roundup (AiTM phishing kits, OAuth consent phishing, AS-REP roasting, MFA fatigue)

---

## Purple-team labs

### Shipped (auto)

<!-- BEGIN AUTO: labs -->

_No purple-team labs shipped yet._

<!-- END AUTO: labs -->

### Backlog (manual)

- [ ] T1059.001 — Atomic Red Team encoded PowerShell tests
- [ ] T1547.001 — Atomic Red Team Run-key tests
- [ ] T1078 — Entra valid-accounts
- [ ] T1021.001 — RDP lateral movement
- [ ] T1055 — process injection

---

## Repo hygiene & infrastructure (manual)

- [ ] **SHA-pin all third-party Actions** — replace tag pins with SHA + tag comment for `DavidAnson/markdownlint-cli2-action`, `lycheeverse/lychee-action`, `crate-ci/typos`, `anthropics/claude-code-action`, `step-security/harden-runner`, `ossf/scorecard-action`, `actions/dependency-review-action`. Dependabot (already enabled) will keep them current.
- [ ] **Promote `harden-runner` from `audit` to `block` mode** in `daily-draft.yml`, `todo-sync.yml`, `daily-reminder.yml`, `discord-reminder.yml` once 1 week of audit-mode runs has produced a stable allowed-endpoints list.
- [ ] **Add `harden-runner` to `lint.yml` and `scorecard.yml`** jobs.
- [ ] **Triage and fix `zizmor` findings**, then tighten its CI step to `--min-severity=medium` (currently runs but doesn't fail the build).
- [x] `LICENSE` (MIT)
- [x] `SECURITY.md`
- [x] `CODEOWNERS`
- [x] `.github/dependabot.yml`
- [x] PR + issue templates
- [x] `COVERAGE.md` (ATT&CK matrix)
- [x] `detections/DATA_SOURCES.md`
- [x] Markdown + link CI
- [x] Sigma validation CI (pysigma)
- [x] Auto-TODO sync workflow
- [x] YARA validation CI
- [x] Spell check (typos) CI
- [x] `CODE_OF_CONDUCT.md`
- [x] Badges on root README (CI status, license, last release)
- [ ] Per-backend "how to deploy" guides (Sentinel analytic rule / Defender custom detection / Splunk savedsearches.conf)

---

## Automation (reminders)

- [x] `daily-reminder.yml` — opens a daily GitHub issue (schedule active)
- [x] `discord-reminder.yml` — daily Discord ping with live CISA KEV data (schedule active)
- [x] `daily-draft.yml` — Tier 3 agentic drafting Mon/Tue (schedule active)
- [x] `todo-sync.yml` — auto-syncs the `BEGIN AUTO` sections of this file
