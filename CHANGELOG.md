# Changelog

All notable changes to this repo are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
