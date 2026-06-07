# Changelog

All notable changes to this repo are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (hardening — new top-level content area)
- **`hardening/compensating-controls.md`** — companion reference for the baseline exception process. Defines what a real compensating control is (vs. theater) via the five-test rule, lists acceptable temporary / permanent substitutes for the most common baseline gaps (organized by Identity / Email / Endpoint / Backup / Logging), explicitly enumerates common proposals that DO NOT count (user training as MFA substitute, "we have a policy", legacy-auth-for-the-printer, etc.), and specifies the seven documentation items every active compensating control must have on file.
- **`hardening/nextlayersec-baseline.md`** — **the non-negotiable security baseline** NextLayerSec enforces on every client tenant in production. 6 sections (Identity / Email / Endpoint / Backup / Logging / IR), each item with explicit *what / verify / why / what-if-not*. Audit procedure, two-type exception process (Type A implementation delay, Type B permanent non-conformance with exec sign-off; explicitly no Type C). Documented as cyber-insurance evidence pack and onboarding gate — gaps must remediate within 30 days or the engagement does not proceed. References the reference guides for the *how* and the threat-intel / case-record content for the *why*.
- **`hardening/` directory bootstrapped.** New content category: prevention-side baselines that complement the existing detect (detections/) + respond (blue-team-playbooks/) content. Includes `README.md`, `_template.md`, two reference guides, and the non-negotiable baseline above.
- **`hardening/entra-id.md`** — 10-policy Conditional Access reference baseline for Entra ID. Includes the rollout order with dependency graph, validation methods using SigninLogs / What-If tool / repo detections, common pitfalls (break-glass exclusion as #1), reversal plan, and crosswalks to MITRE ATT&CK mitigations (M1032 / M1018 / M1036 / M1028 / M1017), NIST CSF 2.0 Subcategories (PR.AA-01/04/05, DE.AE-02), ISO 27001:2022 (A.5.17, A.8.5, A.8.2), CIS Controls v8.1 (5, 6, 13.6, 16.3). Pairs with the Scattered Spider + AiTM phishing-kit threat intel already in the repo.
- **`hardening/windows-endpoint.md`** — Windows 10/11 + Server 2019+ endpoint baseline. Covers EDR onboarding + tamper protection, EDR-in-block-mode, ASR rules (the high-impact 8), LSA-PPL, Credential Guard + HVCI, BitLocker with recovery-key escrow, Smart App Control vs. WDAC, Network Protection, Controlled Folder Access, PowerShell module + script-block logging. 7-stage rollout schedule with per-item reversibility classification (Smart App Control is irreversible — flagged as such). Cross-links every endpoint detection in the repo to a control that prevents the attack the detection is for.
- **`scripts/sync-todo.py`** — discovers `hardening/*.md` and ticks the corresponding TODO section automatically (same auto-sync pattern as detections / playbooks / threat-intel).
- **`.github/workflows/daily-draft.yml`** — new `hardening` lane (manual-dispatch only). To fire two lanes on a single day, dispatch the workflow twice with different lane values. The hardening prompt instructs the agent to pick from the Hardening backlog, follow the template, and bias toward Microsoft 365 Business Premium / E3 / E5 + Defender for Endpoint + Intune.
- `TODO.md` — new "Hardening guides" section with auto-sync block + manual backlog (M365 anti-phish, Defender for Endpoint baseline, Intune, Network, Azure, Sentinel essentials).

### 📒 Week of 2026-06-01 → 2026-06-07

A productive week — every weekday lane shipped its target, the Tier-3 agentic drafter went live for the first time, the auto-merge-after-fact-check gate landed, and the security hardening pass closed three zero-trust-ish gaps (egress audit on every workflow, dependency review on PRs, zizmor running at medium+). Below is the consolidated view; per-PR detail is in the per-batch sections that follow.

**By the numbers (week):**

- **8 PRs merged.** 13 → 16 detection techniques covered, 2 → 3 playbooks, 0 → 1 threat-intel campaign, 0 → 1 TTP roundup.
- **The auto-drafter completed 5 of 7 lanes** (Mon CVE failed pre-key, Sat cleanup failed mid-week on credit balance). Tue / Wed / Thu / Fri ran end-to-end with valid PRs.
- **CSF 2.0 deep-dive** in `frameworks/nist-csf.md` (34 → 190 lines) is the single biggest content piece — pairs the framework's six Functions with the actual repo content in a crosswalk and worked example.
- **Security CI now blocks merges** for: any new vulnerable dependency (`dependency-review`), any new medium+ zizmor finding, any new typo (with the security-acronym allowlist tuned for our content).

**Shipped detections (week, 3 new + cross-source upgrades):**

- T1078.004 — risky Entra sign-in + mailbox-rule mutation (the canonical post-AiTM signal)
- T1566.001 — delivered attachment-phish with credential-harvester link on abused hosting
- (T1071.001, T1486, T1547.001, etc. all already shipped pre-week, COVERAGE.md updated)

**Threat-intel content (week):**

- Campaign: Scattered Spider 2023 casino breaches (the first repo campaign write-up; auto-drafted Thursday)
- TTP: Adversary-in-the-Middle phishing kits (the first repo TTP roundup)

**Operational signals working:**

- Auto-reminder issue every day at 13:00 UTC ✅
- Discord daily lane reminder ✅
- Discord TODO-update on every push that touches `TODO.md` ✅
- Discord push notification on the (private) incidents repo ✅
- Tier-3 agentic drafter Tue/Wed/Thu/Fri ✅; Mon/Sat need a credit top-up on the Anthropic Console
- Auto-merge fact-check gate ✅ (not yet exercised in earnest — drafts have all been small enough to merge by hand)

### Changed (Saturday cleanup lane)
- **`harden-runner` extended to read-only workflows.** Added `step-security/harden-runner@v2` (audit mode) to every job in `.github/workflows/lint.yml` (7 jobs: markdownlint, sigma-validate, yara-validate, typos, linkcheck, zizmor, dependency-review) and to `.github/workflows/scorecard.yml`. The write-permission workflows already had it; this closes the gap on the read-only ones so every runner has an outbound-connection audit trail.
- **Zizmor triaged and gated.** New `.github/zizmor.yml` config: suppresses the tag-pin "blanket policy" noise (49 high-severity findings — tracked separately by the existing "SHA-pin all third-party Actions" TODO item, will be cleared in one motion when Dependabot starts maintaining SHA pins) and excludes the GitHub-managed `codeql.yml` from `artipacked` checks. All medium+ findings fixed by adding `persist-credentials: false` to checkout steps in read-only workflows (lint, daily-reminder, discord-reminder). `discord-todo-update.yml` already had it. `todo-sync.yml` and `daily-draft.yml` intentionally do NOT set `false` because those workflows push commits / open PRs and need the token. Zizmor CI now runs with `--min-severity=medium` (was audit-only) — the build fails on any new medium+ finding.

### Changed (Friday tools/frameworks lane)
- **`frameworks/nist-csf.md` deepened to CSF 2.0** — updated from CSF 1.1 ("5 functions") to CSF 2.0 (6 functions, **Govern** added as the new top-level Function). Now includes: a CSF 1.1 → 2.0 changelog section; a "how to use this in a SOC / MSP engagement" walkthrough (Week 1 kickoff, Week 2–4 roadmap, ongoing operationalization with weekly / quarterly / annual cadence); a full crosswalk of every section of this repo to specific CSF 2.0 Subcategories (`GV.OC`, `ID.AM`, `PR.AA`, `DE.CM`, `RS.MA`, `RC.RP`, etc.); a worked example tracking a phishing incident through all six Functions with the Subcategory tags, the action taken, and the repo file that documents it; a "Common CSF mistakes" section based on field experience; updated references including the CSF Reference Tool and CIS Controls v8.1 → CSF 2.0 crosswalk.

### Added (T1566.001 attachment-phish detection)
- **Detection: T1566.001 — Delivered phish: attachment + credential-harvester link on abused hosting** (KQL + Sigma). Catches the attachment-borne credential phish that bypassed filtering: a delivered inbound email carrying an attachment plus an embedded link to a harvester on abused free / trusted-SaaS hosting (Google Sites, Firebase, Azure Blob, `*.pages.dev`, …), weighted by weak / best-guess sender auth (`SPF=none`, `DMARC=bestguesspass`). The KQL joins `EmailEvents` + `EmailUrlInfo` + `EmailAttachmentInfo` and ships a `UrlClickEvents` clicker check; the Sigma version is a multi-doc `temporal` correlation over `m365_delivered_inbound_with_attachment` and `m365_email_url_abused_hosting`. Fills the T1566.001 detection gap (previously playbook-only).
- **`.typos.toml`** — allowlisted `TABL` (Microsoft Tenant Allow/Block List) so anti-phishing content doesn't trip the spell-checker.

### Coverage (T1566.001 attachment-phish)
- `COVERAGE.md` updates: Initial Access detection count `1 → 2`; T1566.001 row now links the KQL + Sigma detections.

### Added (content + Discord-TODO-notify batch)
- **Detection: T1078.004 — Risky Entra sign-in followed by mailbox-rule mutation** (KQL + Sigma). Highest-fidelity post-AiTM cookie-replay signal. Cross-source join on `SigninLogs` + `OfficeActivity` over a 10-minute window. The Sigma version uses a multi-doc `temporal` correlation across `entra_risky_successful_signin` and `entra_inbox_rule_mutation`. Closes the top item in 🔥 Next up and the direct follow-on detection called out by the AiTM phishing-kits TTP roundup.
- **`.github/workflows/discord-todo-update.yml`** — fires on pushes to `main` that touch `TODO.md`, diffs newly-ticked / newly-added / re-opened items, and posts a single Discord embed with overall progress (`X/Y items done · NN%`). Uses the same `DISCORD_WEBHOOK_URL` secret as the existing daily reminders; warns and exits 0 if unset. Skips silently when only whitespace / auto-counts changed.

### Coverage
- `COVERAGE.md` updates: Initial Access detection count `0 → 1`; T1078.004 row added in the per-technique table.

### Added (security hardening batch)
- **`zizmor` CI job** in `.github/workflows/lint.yml` — purpose-built GitHub Actions YAML linter. Catches script injection via `${{ }}` in `run:` blocks, `permissions: write-all` defaults, `pull_request_target` misuse, and unpinned third-party Actions. Uploads SARIF to GitHub code-scanning (`Security → Code scanning alerts`). Runs in audit mode initially (`--no-error-on-findings`) so existing findings can be triaged before CI hard-fails.
- **`dependency-review` CI job** in `.github/workflows/lint.yml` — flags vulnerable Actions / dependencies introduced in PRs, posts a summary comment on failure, fails the PR on `high`-severity issues.
- **`step-security/harden-runner`** added in **audit mode** to every workflow that holds write permissions:
  - `daily-draft.yml` (contents + pull-requests write — highest risk; also calls Claude over network)
  - `todo-sync.yml` (contents: write — commits sync back to main)
  - `daily-reminder.yml` (issues: write)
  - `discord-reminder.yml` (contents: read — added preemptively because it egresses to Discord)
  Audit mode logs every outbound connection and runner action without blocking. Plan to flip to `block` after 1 week of clean runs once the allowed-endpoints list is stable. New TODO items track the promotion and remaining add-points.

### Follow-ups noted in TODO
- SHA-pin every third-party Action (Dependabot already configured to keep SHA pins current).
- Promote `harden-runner` to `block` mode after baseline.
- Add `harden-runner` to read-only workflows (`lint`, `scorecard`).
- Triage zizmor findings then tighten its severity threshold to `medium`.

### Added (security + Thursday threat-intel batch)
- **`.github/workflows/scorecard.yml`** — OpenSSF Scorecard analysis on every push to `main` and weekly (Mon 13:23 UTC). Uploads SARIF to GitHub Code-scanning so findings appear under Security → Code scanning alerts, and publishes to the OpenSSF API so a public Scorecard badge can be added once the first run completes.
- **TTP roundup:** `threat-intelligence/ttps/aitm-phishing-kits.md` — Adversary-in-the-Middle phishing kits (evilginx2 / Modlishka / Tycoon 2FA / Mamba 2FA / NakedPages / Greatness / Caffeine / Storm-1575). Mapped to T1557 / T1606.002 / T1078.004 / T1556.006 / T1539; cross-links to Scattered Spider profile and the password-spray + beaconing detections; full defender playbook from prevention through containment.

### Changed (security)
- **`crate-ci/typos@master` → `crate-ci/typos@v1`** in `.github/workflows/lint.yml`. Pinning to the major-version tag removes the moving-target supply-chain risk of running whatever the branch tip is on every CI run.

### Added (hygiene batch)
- `CODE_OF_CONDUCT.md` — adopts Contributor Covenant 2.1 by reference, with project scope and reporting path.
- `.github/workflows/lint.yml` gains two new jobs:
  - `yara-validate` — installs `yara` and validates every `.yar` / `.yara` rule in `detections/yara/`, including templates (parse-only).
  - `typos` — runs `crate-ci/typos` against the whole repo with a project config.
- `.typos.toml` — spell-check config with sensible ignore rules for security content (hex / base64 / hashes / CVE IDs / KB IDs / MITRE technique IDs / Sigma UUIDs) and excludes for query files (`*.kql`, `*.spl`, `*.yar*`) and the auto-generated `TODO.md`.
- Root `README.md` now sports CI / license / Code-of-Conduct / last-commit badges across the top.

### Changed (consolidation)
- All in-flight work consolidated onto a single branch and PR. The actions/checkout bump from Dependabot PR #6 was rolled in (v4 → v6 across `discord-reminder`, `lint`, `todo-sync`, `daily-reminder`, `daily-draft`; `codeql.yml` left untouched as GitHub-managed default setup).
- CVE-selection priority list expanded: added **SonicWall** to the network/identity-gear bucket, plus a new dedicated bucket for **popular third-party endpoint software on Windows fleets** (Google Chrome, Microsoft Edge, Firefox, Adobe Reader/Acrobat, 7-Zip, WinRAR, Notepad++, Zoom, Slack, Java/OpenJDK, .NET runtime). Updated `vulnerabilities/README.md`, `CONTRIBUTING.md`, and the Mon CVE prompt in `daily-draft.yml`.

### Changed (CVE selection bias)
- CVE selection now prioritizes the Windows / MSP environment in this order: (1) Microsoft Windows ecosystem; (2) edge/identity/virtualization gear deployed alongside Windows fleets (Fortinet, Cisco, Palo Alto, Citrix, Ivanti, VMware, F5, Atlassian, MOVEit, ConnectWise, Veeam, Kaseya, SolarWinds); (3) CISA KEV entries with public PoC / ITW exploitation; (4) other only as fallback.
- `vulnerabilities/README.md`, `CONTRIBUTING.md`, and the Mon CVE prompt in `.github/workflows/daily-draft.yml` updated to encode the same priority.

### Added (eighth batch — Mon CVE + Tue detection + Wed playbook)
- **Mon CVE:** `vulnerabilities/CVE-2022-0492.md` — Linux kernel cgroups v1 `release_agent` container escape. CISA KEV (added 2026-06-02). Includes remediation (patch / drop `CAP_SYS_ADMIN` / cgroups v2 / userns), detection guidance (auditd + Falco), and full framework mapping (ATT&CK T1611/T1068/T1610, NIST CSF 2.0, ISO 27001, CIS).
- **Tue detection:** KQL + Sigma rule `T1071.001_beaconing-rare-https` — sustained outbound HTTPS to fleet-rare destinations (C2 beacon shape). Fills the **Command & Control** tactic gap in COVERAGE.md. Sigma is a base-rule + `event_count` correlation; documented SIEM-side rarity-aggregation note for backends without native cardinality conditions.
- **Wed playbook:** `blue-team-playbooks/ransomware-outbreak.md` — Critical-severity, full lifecycle from trigger through lessons-learned, with explicit timing ("first 15 minutes", "next 30 minutes"), backup-protection step, krbtgt double-reset, and cross-links to the T1486/T1003.001/T1547.001/T1071.001 detections plus the Scattered Spider profile.
- `vulnerabilities/README.md`, `blue-team-playbooks/README.md`, `detections/{kql,sigma}/README.md`, `COVERAGE.md`: indexes and counts updated.

### Added (seventh batch — Persistence detection + Identity tooling + TODO rewrite)
- KQL + Sigma detection: **T1547.001 Run / RunOnce key persistence by non-installer process**, including a Sigma rule with `selection_runkey and selection_writeop and not 1 of filter_*`. Fills the Persistence tactic gap in `COVERAGE.md` (now 1).
- `tools/blue-team-tools.md` rewritten with five new sections: **Identity & Cloud Attack Analysis** (ROADtools, AzureHound + BloodHound CE, ScubaGear, Monkey365, Hawk, 365Inspect, AADInternals), **Endpoint Triage & Memory** (KAPE, Velociraptor, Volatility 3, Sysinternals, sigma-cli), **Threat Intel Feeds** (AbuseIPDB, OTX, MalwareBazaar, ThreatFox, URLhaus, PhishTank), **Purple Team** (Atomic Red Team, Caldera, PurpleSharp, Stratus), and an expanded **Framework Helpers** section. Pairs directly with the Scattered Spider profile.
- `TODO.md` rewritten — top-of-file "🔥 Next up" section ordered by realistic ship value; shipped items kept with links as a work log; new "Automation (reminders)" section documenting that schedules are disabled and pointing at the dispatch path.

### Changed
- **Daily-draft workflow extended to all 7 days.** `daily-draft.yml` now fires every day (`30 13 * * *`) and dispatches to a day-specific Claude prompt — Mon CVE, Tue detection, Wed playbook, Thu threat intel, Fri tools/frameworks, Sat repo-hygiene fix, Sun weekly review.
- **Auto-merge gate added** at the end of `daily-draft.yml`: a regex precheck rejects any `TBD — verify` / `FIXME` / `XXX` marker; an adversarial Claude fact-check then verifies CVE IDs, MITRE technique IDs, KQL/Sigma syntax, cross-references, and that factual claims have citations. If both pass, the PR is marked ready and GitHub native auto-merge (`--auto --squash --delete-branch`) is enabled — the merge waits for required CI checks. If either fails, the PR stays draft with a `needs-review` label and a comment explaining why.
- Kill switch: repo variable `AUTO_MERGE_ENABLED=false` gates the merge step without disabling the fact-check itself.
- All three reminder workflow schedules are **re-enabled** (`daily-reminder.yml`, `discord-reminder.yml`, `daily-draft.yml`).

### Added (auto-TODO sync)
- `scripts/sync-todo.py` — discovers shipped detections, playbooks, workflows, CVEs, threat-intel notes, and purple-team labs from the filesystem and regenerates the `BEGIN AUTO` / `END AUTO`-marked sections of `TODO.md`. Idempotent; runs locally too.
- `.github/workflows/todo-sync.yml` — runs the sync on push to `main` (commits the update with `[skip ci]`) and runs `--check` on PRs touching content (PR fails if its TODO is stale).
- `TODO.md` restructured with marker comments so manual notes (🔥 Next up, manual backlogs, hygiene checklist) stay intact while the shipped lists auto-update.

### Added (sixth batch — Sigma rules + data-source map + CI)
- Ported all four KQL detections to vendor-neutral **Sigma** rules in `detections/sigma/`, each with a `.md` sibling mirroring the KQL note structure:
  - `T1059.001_powershell-encoded-command` (process_creation, level medium).
  - `T1003.001_lsass-access-suspicious` (process_access, `selection and not filter_known`, level high).
  - `T1110.003_entra-password-spray` — base rule + `value_count` correlation (single IP, ≥10 distinct users / 1h), level high.
  - `T1486_mass-file-rename-ransomware` — base rule + `event_count` correlation (≥50 renames per process / 15m), level critical.
- `detections/DATA_SOURCES.md` — matrix (Defender XDR table / Sentinel table / Sysmon EID / Entra connector / min retention) plus per-rule detail, sourced from the KQL/Sigma siblings.
- `.github/workflows/lint.yml` — new `sigma-validate` job: installs `pysigma==1.3.3` and validates every non-template `detections/sigma/*.yml` via `SigmaCollection.from_yaml`.
- `detections/sigma/README.md` index table; `COVERAGE.md` detection cells now link both KQL and Sigma for the four ported techniques.
- The two correlation rules document a "SIEM-side aggregation" fallback (threshold semantics + `sigma convert`) for backends lacking native correlation support.

### Added (fifth batch — Discord automation)
- `.github/workflows/discord-reminder.yml` (Tier 2) — daily Discord webhook ping with **live data**: newest CISA KEV additions not yet in the repo on CVE day, a rotating uncovered ATT&CK technique on detection day, lane focus + links the rest of the week.
- `.github/workflows/daily-draft.yml` (Tier 3) — Mon/Tue scheduled Claude Code run that **drafts** the day's CVE or KQL detection and opens a **draft PR** for review, then pings Discord. Marks unverified facts "TBD — verify".
- `.github/AUTOMATION.md` — documents all three reminder workflows, the required secrets (`DISCORD_WEBHOOK_URL`, `ANTHROPIC_API_KEY`), testing, cost/safety notes, and tuning.
- Existing `daily-reminder.yml` (GitHub issue) retained alongside the new Discord workflows.

### Added (fourth batch — first threat-intel content)
- Actor profile: **Scattered Spider (UNC3944 / Octo Tempest / Muddled Libra)** — TTP table mapped to MITRE ATT&CK, tooling notes, cross-links to the password-spray and LSASS detections already in the repo, and concrete defender guidance (phishing-resistant MFA, help-desk hardening, device registration restrictions, RMM monitoring, PIM, CAE, SaaS specifics).
- `threat-intelligence/README.md` index updated with the new actor entry.

### Added (third batch — repo trust + discovery)
- `LICENSE` — MIT.
- `SECURITY.md` — private vulnerability reporting policy, scope, SLAs.
- `.github/dependabot.yml` — weekly GitHub Actions version updates (would have caught the lychee-action advisory automatically).
- `.github/CODEOWNERS` — auto-request review on every PR.
- `.github/PULL_REQUEST_TEMPLATE.md` — pre-filled contributor checklist.
- `.github/ISSUE_TEMPLATE/` — structured forms for new CVEs, detections, playbooks, and tuning requests; private-security and discussions contact links.
- `COVERAGE.md` — live MITRE ATT&CK coverage matrix with per-tactic counts and a prioritized gap list.
- Root `README.md` links to license, security policy, and coverage map.

### Added (second batch)
- KQL detection: `T1110.003_entra-password-spray` (single IP / many users / failed sign-ins).
- KQL detection: `T1003.001_lsass-access-suspicious` (non-MS process opens LSASS with dump rights).
- KQL detection: `T1486_mass-file-rename-ransomware` (ransomware encryption canary).
- Real playbook: `blue-team-playbooks/phishing-email-triage.md` (trigger → triage → containment → eradication → recovery → lessons learned, with ATT&CK / NIST CSF / ISO 27001 mapping).
- KQL index in `detections/kql/README.md` updated with all four current rules.
- TODO checked off the items shipped here.
- `.github/workflows/daily-reminder.yml` — daily 8 AM CT scheduled workflow that opens a `daily-reminder`-labeled issue with today's TODO lane (CVE / Detection / Playbook / Threat-intel / Tools / Cleanup / Changelog) and assigns it to the maintainer.

### Fixed
- Resolved markdownlint failures from PR #2 by relaxing stylistic rules and fixing real issues (double-space `##` heading, trailing blank lines, broken README anchor).
- Bumped `lycheeverse/lychee-action` from `v1` to `v2` to clear the moderate Dependabot advisory.

### Added
- `detections/` directory with `kql/`, `sigma/`, `yara/`, `splunk/` subfolders, READMEs, and templates.
- First KQL detection: `T1059.001_powershell-encoded-command` (query + markdown sibling).
- `blue-team-playbooks/README.md` index + `_template.md`.
- `detection-workflows/README.md` index + `_template.md`.
- `vulnerabilities/README.md` index.
- `purple-team-labs/` scaffolding with `_template/` directory.
- `threat-intelligence/` scaffolding with `actors/`, `campaigns/`, `ttps/` and per-type templates.
- `CONTRIBUTING.md`, `CHANGELOG.md`, `TODO.md`.
- GitHub Actions workflow for markdown lint + link checking.
- Updated root `README.md` to reflect new structure.

## How to update

When you merge a PR, add a bullet under `[Unreleased]`. When you cut a release, rename `[Unreleased]` to the version and date and start a new `[Unreleased]` section above it.
