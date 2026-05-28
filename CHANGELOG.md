# Changelog

All notable changes to this repo are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
