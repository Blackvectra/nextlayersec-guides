# Changelog

All notable changes to this repo are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (docs site — MkDocs Material on GitHub Pages at docs.nls-assessment.app)
- **`mkdocs.yml` added** — MkDocs Material site config. Mirrors the repo's information architecture into an explicit `nav:` block (Detections / Playbooks / Hardening / Threat-intel / Vulnerabilities / Frameworks / Tools / Contributing / About). Material features turned on: tabbed top nav, expanded sidebar sections, full-text search with highlighting + suggestions, dark-mode toggle (Material default palette + slate), copy-to-clipboard on code blocks, mermaid diagram support, admonitions for the baseline callouts. Repo-style icons (GitHub fork-corner, edit-pencil + view-eye action buttons on every page).
- **`requirements-docs.txt` added** — `mkdocs-material>=9.5,<10` + `mkdocs-awesome-pages-plugin>=2.9,<3`. Tracked separately from `requirements-ci.txt` so the lint / sigma-validate / zizmor jobs don't rebuild for docs-dep bumps. Dependabot's `pip` ecosystem at `/` already monitors all `requirements*.txt` so no config change needed.
- **`scripts/build-docs.sh` added** — stage script. MkDocs forbids `docs_dir` being the config-file parent, so we can't point it at the repo root directly. The script copies the content directories (`detections/`, `hardening/`, `blue-team-playbooks/`, `threat-intelligence/`, `vulnerabilities/`, `frameworks/`, `tools/`, `detection-workflows/`, `purple-team-labs/`, `docs/`) plus root-level pages (`README.md`, `COVERAGE.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`, `LICENSE`) into `_docs/` and mkdocs builds from there. Uses plain `find`+`cp` (no rsync dependency) so it runs on minimal images.
- **`.github/workflows/docs-deploy.yml` added** — build + deploy to GitHub Pages. Two-job pipeline: `build` (harden-runner audit + disable-sudo-and-containers, checkout, setup-python, install requirements-docs, run `bash scripts/build-docs.sh`, `mkdocs build`, copy CNAME + static assets, `actions/upload-pages-artifact@v4`) → `deploy` (separate job with `pages: write` + `id-token: write` perms, calls `actions/deploy-pages@v4`, environment `github-pages` with the deployed URL). Path-filtered triggers: any `*.md` change, `mkdocs.yml`, `requirements-docs.txt`, `docs-static/**`, `scripts/build-docs.sh`, the workflow itself. Plus weekly Sunday rebuild + manual dispatch. Wired into the failure-notify reusable.
- **`docs-static/CNAME` added** — `docs.nls-assessment.app`. Copied into the Pages artifact at build time so the custom domain is preserved across every deploy.
- **`docs-static/robots.txt` added** — allow-all + sitemap pointer.
- **`.gitignore` extended** — `_docs/` (build staging) + `site/` (mkdocs output).
- **`README.md` badges** — added `docs.nls-assessment.app` site badge + an inline link to the rendered site at the top of the README.

#### DNS configuration needed (one-time, manual)

The Pages deployment will succeed without DNS but the custom domain won't resolve until you add the DNS records at the registrar / Cloudflare for `nls-assessment.app`:

| Type | Host | Value | TTL |
|---|---|---|---|
| `CNAME` | `docs` | `blackvectra.github.io.` | 300 |

Then in the repo: Settings → Pages → Custom domain → `docs.nls-assessment.app` → Save → enable Enforce HTTPS once the cert provisions (~10 min after DNS propagates).

### Added (Mon CVE — Ivanti Sentry OS Command Injection)
- **`vulnerabilities/CVE-2026-10520.md`** — Ivanti Sentry OS Command Injection, CISA KEV-listed 2026-06-11. MSP-relevant (Sentry is the mobile-device gateway proxying ActiveSync / EAS / SharePoint for every managed phone). Covers impact (full appliance compromise as Sentry service user, ActiveSync / OAuth token theft, pivot to Exchange / SharePoint / LDAP via stored connector credentials, pivot to MobileIron Cloud, persistence via webshell / cron / systemd), 8-step remediation (emergency patch, restrict mgmt-plane exposure, rotate every appliance credential including SSH keys and connector service accounts, revoke ActiveSync tenant-wide via `Clear-MobileDevice`, audit appliance filesystem for persistence indicators, audit syslog for exploitation signature, consider rebuild on any compromise evidence), detection guidance (anomalous shell-spawn from Sentry service user, POST requests with shell metacharacters, new outbound connections, config-file changes outside admin windows). Framework crosswalk: ATT&CK T1190/T1059.004/T1505.003/T1552.001/T1606.001; NIST CSF 2.0 PR.AA-05 + DE.CM-04 + RS.AN-06 + RS.MI-01 + PR.IR-01. Vendor CVSS and KB number marked TBD-verify pending direct PSIRT access.

### Added (Tue Detection — T1053.005 Scheduled task by non-installer, second Persistence coverage)
- **`detections/kql/T1053.005_scheduled-task-by-non-installer.kql`** — surfaces scheduled-task creates / changes (schtasks.exe /create or /change, legacy at.exe with UNC target, PowerShell `*-ScheduledTask*` cmdlets) when the initiating process is NOT on the known-installer allowlist. Four boolean tag columns: `B_NotInstaller` (entry condition — parent not on installer allowlist), `B_WritableInit` (parent from `\AppData\`/`\Public\`/`\ProgramData\`/`\Temp\`), `B_UnsignedInit` (parent has no signer info or "Unknown"), `B_LolbinSink` (task action invokes powershell/mshta/rundll32/regsvr32/wmic/msbuild/cscript/wscript/installutil/msxsl). `RiskScore = 3·WritableInit + 2·UnsignedInit + 2·LolbinSink + NotInstaller`; `Severity` auto-raises to High on any of the three high-fidelity tags.
- **`detections/kql/T1053.005_scheduled-task-by-non-installer.md`** — intent / data sources (DeviceProcessEvents primary; Windows EVTX 4698/4702/4699 fallback) / logic / FP (in-house deployment tools, vendor agents, developer workflows) / tuning (signer allowlist upgrade, LOLBin sink tightening, hidden-name branch suggestion, volume tuning) / output-data sensitivity note / response (snapshot task XML before deletion, pivot parent + action, hunt fleet-wide).
- **`detections/sigma/T1053.005_scheduled-task-by-non-installer.yml`** — Sigma equivalent. Three selectors (schtasks_create, at_legacy, powershell_create) and a `legit_installer_parent` exclusion. Validates against pysigma. Real UUID `28fb2fe2-…`. Level: medium.
- **`detections/sigma/T1053.005_scheduled-task-by-non-installer.md`** — sibling with per-backend conversion notes (Defender XDR / Sentinel / Sysmon / Splunk / Elastic) + tuning levers.
- **`COVERAGE.md`** — T1053.005 row added; per-tactic counter for TA0003 Persistence bumped 1 → 2.

### Added (Wed Playbook — Cloud Account Compromise, first Cloud-IR playbook)
- **`blue-team-playbooks/cloud-account-compromise.md`** — first cloud-IR playbook focused on Microsoft 365 / Entra ID account compromise. Trigger list (T1078.004 / T1110.003 / T1021.001 detections, Defender for Cloud Apps risk events, Identity Protection High-risk users, user self-reports, MS Threat Intelligence breach-data matches). Scope-determination by tier of compromised principal + compromise method (password spray, AiTM/token theft, OAuth consent phishing, stolen device session, insider) + persistence touched + data exfiltrated check. 5-step triage. 7-step per-account containment + 5-step tenant-wide containment (with service-principal branch). 9-step eradication covering mailbox inbox rules with KQL query examples, mailbox delegate / forwarding permissions, OAuth consents, application impersonation RBAC, SharePoint / OneDrive recent shares with audit log query, Teams chats from the account, hybrid AD logon audit, service-credential rotation, customer-facing IOC rotation for MSP context. Recovery + lessons-learned templates. Framework crosswalk to ATT&CK T1078.004/T1556/T1098.001/T1114.002/T1530/T1199, NIST CSF 2.0, ISO 27001:2022, CIS Controls v8.1.

### Changed (Cleanup — .editorconfig + validator hygiene + COVERAGE)
- **`.editorconfig` added** — repo-wide editor defaults. UTF-8 + LF + final-newline + no-trailing-whitespace base. Per-extension overrides: markdown 2-space indent + preserve trailing double-space (hard line breaks), YAML/TOML/JSON 2-space, Python 4-space + 100-col, shell 2-space, KQL/SPL/YARA 4-space no-max-line-length, Makefile preserves tabs.
- **`scripts/validate_content.py`** — added `_docs` and `site` to `SKIP_PATHS` so the MkDocs build-staging / output directories don't pollute the internal-link audit when local devs forget to clean before running the validator.

### 📒 Week of 2026-06-08 → 2026-06-14

A full-week ship — all six lanes (CVE / Detection / Playbook / Threat-intel / Tools-frameworks / Hygiene) shipped in one PR. T1218.011 (Defense Evasion) landed earlier in the week as a separate PR; this batch closes the next-biggest priority gap (Lateral Movement) plus the matching playbook and threat-intel cross-link.

**By the numbers (week):**

- **3 PRs merged so far** (PR #47 harden-runner tightening, PR #49 T1218.011, this PR pending).
- **Detection coverage:** 9 → 10 ATT&CK techniques covered; **2 → 4** tactics with at least one Detection (TA0005 Defense Evasion + TA0008 Lateral Movement added).
- **Playbook coverage:** 3 → 4 playbooks; first Credential Access playbook lands.
- **Threat-intel coverage:** 1 → 2 actor profiles; FIN7 alongside Scattered Spider — the two highest-leverage actor profiles for a Windows-MSP defender.
- **Hardening surface unchanged at 4 guides** (Entra ID / Windows endpoint / non-negotiable baseline / compensating controls).
- **Repo-hygiene:** SUPPORT.md added (closes a GitHub community-standards gap); README badges expanded to surface OpenSSF Scorecard, secret-scan, and OSV-Scanner status.

### Added (Monday CVE lane — CVE-2026-0257 PAN-OS Authentication Bypass)
- **`vulnerabilities/CVE-2026-0257.md`** — Palo Alto Networks PAN-OS authentication bypass, CISA KEV-listed 2026-05-29. Covers impact (full management-plane takeover including rule-base / NAT / decrypt-policy disclosure, persistence via backup admin accounts, decrypt-on-policy plaintext access, lateral pivot from management VLAN), 8-step remediation (emergency patch, restrict mgmt-plane exposure, rotate credentials, audit rule base for unauthorized adds, check backup admin accounts, force re-auth, hunt for IOC in system.log/config.log), detection guidance (failed-then-success admin logins from new source, config commits from unexpected source, new admin users in config.log), and framework crosswalks (ATT&CK T1190/T1078/T1556, NIST CSF 2.0 PR.AA-05 + DE.CM-04 + RS.AN-06, ISO 27001:2022 A.8.5/A.8.20/A.5.23, CIS Controls v8.1 6/12/13). Several fields marked "TBD — verify" pending direct PSIRT advisory access (vendor CVSS / KB number).

### Added (Tuesday Detection lane — T1021.001 Lateral Movement)
- **`detections/kql/T1021.001_rdp-unusual-source.kql`** — first repo coverage for **Lateral Movement (TA0008)**. Surfaces successful interactive RDP logons (`LogonType == "RemoteInteractive"`, `ActionType == "LogonSuccess"`) with three independent tag columns: `B_External` (RFC-routable public source IP), `B_UnexpectedInt` (internal source NOT on per-env `adminSubnets` / `jumpHosts` allowlist), `B_SuccessAfterFails` (success preceded by ≥ 5 failures in 10 minutes per `(DeviceName, RemoteIP)` pair via leftouter self-join). `RiskScore = 3·External + 3·SuccessAfterFails + 2·UnexpectedInt`; `Severity` auto-raises to High on External or SuccessAfterFails.
- **`detections/kql/T1021.001_rdp-unusual-source.md`** — intent / data sources (`DeviceLogonEvents` + EVTX 4624 LogonType 10 equivalent) / logic / FP (site-to-site partners, pen-test windows, mis-configured admin subnets) / tuning (`B_UnexpectedInt` precision via Entra device-ID join, `B_SuccessAfterFails` threshold / window adjustment, tier-dial by account class) / output-data sensitivity note / response (validate, pivot on account + source IP, snapshot target, revoke sessions, hunt fleet-wide).
- **`detections/sigma/T1021.001_rdp-unusual-source.yml`** — Sigma high-precision external-source branch (the only one expressible portably). EventID 4624 + LogonType 10 + IpAddress regex excluding RFC1918/CGNAT/loopback/IPv6-ULA. Validates against pysigma. Level: high.
- **`detections/sigma/T1021.001_rdp-unusual-source.md`** — sibling explaining that this is the high-precision external-source branch only; the internal-source + success-after-fails branches live in the KQL companion because they need per-environment context and a time-window self-join.

### Added (Wednesday Playbook lane — Credential Theft / Password Spray)
- **`blue-team-playbooks/credential-theft-password-spray.md`** — first **Credential Access** playbook. Triggers (T1110.003 spray detection / T1078.004 risky sign-in + mailbox rule / T1021.001 RDP with `B_SuccessAfterFails` / Defender Identity Protection risk events / user self-report). Scope-determination (account tier, auth source, single-account vs campaign, MFA status). 5-step triage (first 15 min). 6-step per-account containment (revoke sessions, force password reset, force MFA re-enroll, block sign-in for high tier, audit auth methods for attacker-added persistence, audit CA exclusions). 4-step tenant-wide containment (block source IP at perimeter + CA, block anomalous user-agent, lower CA risk threshold 24-48h, tenant-wide signature search). 6-step eradication (mailbox rules, OAuth consents, mailbox forwards, SharePoint shares, Teams chats, on-prem AD logons). Service-credential rotation. Recovery (restore access, monitor sign-ins 14d, MFA step-up CA 30d, communicate). Lessons-learned template required for every incident (initial vector / MFA bypass class / CA gap / time-to-detection / time-to-containment / time-to-eradication / baseline gap closed). Framework crosswalks.

### Added (Thursday Threat-intel lane — FIN7 actor profile)
- **`threat-intelligence/actors/fin7.md`** — second repo actor profile (after Scattered Spider). FIN7 / Carbon Spider / Sangria Tempest / GOLD NIAGARA / Carbanak Group / ITG14. Covers motivation (financial, full-stop), origin (Russian-speaking, multiple U.S. indictments, continuing operation), business model (centralized crew + RaaS affiliate). Target verticals with the **MSP-targeting pattern explicitly called out** (trojanized secure-file submissions, job-application phishing, fake software-vendor outreach, supply-chain attacks against MSP tools — directly relevant to NextLayerSec's threat model). Tradecraft by ATT&CK tactic (Initial Access via macro/SVG/LNK/ISO/IMG + social-engineering phone calls; PowerShell + WScript + MSHTA execution; Run-key + scheduled-task persistence; stolen creds + RDP + PSExec + WMI + Cobalt Strike lateral movement; LSASS + DPAPI + Kerberoasting credential access; AMSI/ETW bypasses + DLL side-loading + BYOVD defense evasion; ransomware-affiliate impact across BlackBasta / ALPHV / Royal / Maze / REvil). 8-item defensive priority list (phishing-resistant MFA, ASR rules block-mode + SAC, EDR with tamper protection, LSA-PPL + Credential Guard, External Remote Services hygiene, egress filtering, offline-immutable backups, MSP-tenant segregation). Hunt patterns (CS named-pipe signature, AMSI-bypass strings, rundll32 abuse, LSASS access from non-MS processes, mailbox-forwarding rules from anomalous sources). Cross-links every relevant detection / playbook / hardening guide in the repo.

### Added (Friday Tools/frameworks lane — README badges)
- **`README.md` badges expanded** — added OpenSSF Scorecard (`api.scorecard.dev`), gitleaks secret-scan, and OSV-Scanner status badges. The Scorecard badge in particular makes the security posture publicly visible in a single number; prospective contributors can see at a glance whether the project is actively maintained and security-hardened.

### Added (Saturday Hygiene lane — SUPPORT.md + repo-health required-file)
- **`SUPPORT.md` added** — closes the GitHub community-standards gap (Insights → Community Standards now ✅ on every required item). Documents where SOC users / contributors / security reporters / general-question askers go for each kind of help, plus an explicit "where this project does NOT help" section that filters out vendor-product step-by-step questions and compliance-document-template requests.
- **`.github/workflows/repo-health.yml`** — `SUPPORT.md` added to the required-files list so its accidental deletion fires CI within a week of a refactor.

### Changed (Sunday Review lane — coverage rollup + TODO refresh)
- **`COVERAGE.md`** — T1021.001 (Lateral Movement) row added; per-tactic counters updated (Credential Access 2 → 2 detections + 1 playbook; Lateral Movement 0 → 1 detection + 1 playbook). FIN7 row added to "Threat actors profiled".
- **`TODO.md`** — auto-sync ticked the new CVE / detection / playbook / actor files. "Next up" list rotated: shipped items removed; next-up rotation surfaces the per-backend deploy guides (Sentinel / Splunk / Sigma) and the SHA-pin sweep as the top items.

### Added (T1218.011 — first Defense Evasion detection)
- **`detections/kql/T1218.011_rundll32-unusual-cmdline.kql`** — surfaces `rundll32.exe` invocations matching five high-fidelity abuse patterns: protocol-handler bridge (`javascript:`, `vbscript:`, `data:`, `mshtml,RunHTMLApplication`, `url.dll,FileProtocolHandler`), UNC or HTTP DLL paths, world-writable directories (`\AppData\`, `\Public\`, `\ProgramData\`, `\Temp\`), disguised payload extensions (`.tmp` / `.dat` / `.png` / `.jpg` / `.log` / `.txt` / `.zip` / `.bin` / `.rar`), and no-args launches. Each pattern is tagged as its own `B_*` boolean column for fast SOC pivoting; `RiskScore` rolls them up; `Severity` auto-raises to High on the protocol / UNC / HTTP / world-writable-with-non-MS-parent combinations. Microsoft-signed UI plumbing (`shell32,Control_RunDLL`, `printui,PrintUIEntry` from `explorer.exe` / `spoolsv.exe` / etc.) is allowlisted via a `knownLegitParents` list — but only when the only fired flag is the weak ones (`B_WeirdExt` / `B_NoArgs`); protocol / UNC / world-writable patterns fire regardless of parent.
- **`detections/kql/T1218.011_rundll32-unusual-cmdline.md`** — full intent / data sources / logic / FP / tuning / response writeup. Includes an Output-data sensitivity section flagging that `ProcessCommandLine` exports can carry credential-on-cmdline patterns; trim or hash before forwarding to non-need-to-know alert sinks.
- **`detections/sigma/T1218.011_rundll32-unusual-cmdline.yml`** — Sigma equivalent. Five branches under a `rundll32` ancestor, condition `rundll32 and (protocol_bridge or unc_or_http_dll or writable_path or weird_extension or no_args)`. Validates against pysigma (`OK detections/sigma/T1218.011_rundll32-unusual-cmdline.yml`). Real UUID. References the KQL companion.
- **`detections/sigma/T1218.011_rundll32-unusual-cmdline.md`** — sibling explaining each branch + backend-conversion notes (Defender XDR / Sentinel / Sysmon / Splunk / Elastic) + tuning levers.
- **`COVERAGE.md`** — first Defense Evasion row added; per-tactic counter for TA0005 bumped 0 → 1.
- **`TODO.md`** — auto-sync ticked the T1218.011 backlog entry; "Next up" list shifts the rundll32 item from open to shipped.

### Changed (additional security hardening — harden-runner promoted + persist-credentials gap closed)
- **`step-security/harden-runner` config promoted** on 16 workflows from `disable-sudo: true` to **`disable-sudo-and-containers: true`** (a stronger flag that ALSO blocks Docker / containerized execution). This shrinks the runner's attack surface: a compromised dependency can no longer pivot via `sudo` OR via spawning a privileged container to break out of the runner's user-namespace sandbox.
  - Affected: `_notify-failure.yml`, `content-correctness.yml`, `daily-draft.yml`, `daily-reminder.yml`, `dependabot-auto-merge.yml`, `discord-reminder.yml`, `discord-todo-update.yml`, `kev-watch.yml`, `lint.yml` (6 jobs — `markdownlint`, `sigma-validate`, `typos`, `linkcheck`, `zizmor`, `dependency-review`), `patch-tuesday.yml`, `repo-health.yml`, `scorecard.yml`, `secret-scan.yml`, `stale.yml`, `todo-sync.yml`, `workflow-guard.yml`.
  - Intentionally NOT promoted:
    - `lint.yml` `yara-validate` job — needs `sudo apt-get install -y yara` and already overrides to `disable-sudo: false`.
    - `osv-scan.yml` — runs `google/osv-scanner-action` which is a Docker container action (`ghcr.io/google/osv-scanner-action`), so containers must stay enabled.
    - `codeql.yml` — GitHub-managed default-setup, hand-edits get clobbered.
- **`persist-credentials: false` gap closed** on `discord-todo-update.yml`. This workflow only reads the diff to post to Discord — it does not push commits — so the persisted git credential was unnecessary attack surface. Other workflows still missing the flag (`daily-draft.yml`, `todo-sync.yml`) legitimately need the credential to push branches / commit, so left as-is.
- **Zizmor revalidation**: clean at `--min-severity=medium` after the change (4 ignored, 55 suppressed). No findings introduced.

### Fixed (comprehensive security audit findings)
- **HIGH — public-repo leak of private incidents repo:** `hardening/nextlayersec-baseline.md` contained an explicit link to the private `nextlayersec-incidents` repo (`https://github.com/Blackvectra/nextlayersec-incidents`) plus a specific client name (`bchabis.com`) plus an internal file path (`phishing/2026-06-04-bchabis-com.md`). All three were a recon target — they confirmed the private repo's existence, named a real tenant, and gave attackers a known path to look for. Redacted to generic language across `nextlayersec-baseline.md` (3 spots) and `docs/github-settings.md` (1 spot).
- **HIGH — output-data sensitivity for the T1566.001 KQL detection:** the `project` clause exports `Subject` and `RecipientEmailAddress`, both of which can carry sensitive content (HR / legal / M&A vocabulary; small privacy disclosure). Added a new `## Output-data sensitivity` section to `detections/kql/T1566.001_attachment-link-credential-harvester.md` documenting the RBAC trade-off and providing a safe minimal projection alternative. The KQL itself is unchanged — analysts usually need the subject for triage; the tuning guidance lets each org make the right call for their alert pipeline.
- **MED — `scripts/validate_content.py` symlink path-traversal defense:** the internal-link audit now skips symlinks in the source-file walk via `if path.is_symlink(): continue`. No symlinks exist in the repo today, but defense-in-depth — a future committed symlink could redirect the validator outside `REPO_ROOT` despite the existing `relative_to(REPO_ROOT)` check on the resolved target.
- **MED — `scripts/validate_content.py` `ATTACK_BUNDLE_URL` pinned:** was pointing at `master` (mutable ref) which would inject bogus technique IDs into our allowlist if `mitre-attack/attack-stix-data`'s default branch were ever compromised. Pinned to release tag `v17.1`. Re-pin when MITRE publishes a new ATT&CK version (validator still passes; loaded 679 non-deprecated techniques).
- **MED — `.github/workflows/todo-sync.yml` push race:** `git push` after the auto-sync commit lacked rebase retry. If another commit landed on `main` between our commit and our push (Dependabot merge, a fresh push triggering a concurrent auto-sync run, etc.) the push would fail silently. Added a 3-attempt rebase-on-conflict retry loop with explicit failure annotation on persistent conflicts.
- **LOW — `.github/allowed-actions.txt`:** explicit comment now notes `actions/dependency-review-action` as one of the actions covered by the `actions/` owner prefix.
- **LOW — `.gitleaks.toml`:** added a comment block noting the assumption that GitHub native push protection is enabled, with a pointer to the `docs/github-settings.md` runbook section that documents the toggle.

### Verified — no fix needed (false-positive findings from the audit)
- **`.github/workflows/scorecard.yml`:** the `notify-on-failure` job was flagged for lacking a `github.event_name != 'pull_request'` guard. Scorecard has **no `pull_request` trigger** at all (`branch_protection_rule`, `schedule`, `push` to main, `workflow_dispatch` only), so the guard isn't needed; no PR-context exposure of the Discord webhook can happen.
- **`.github/workflows/kev-watch.yml`:** the CVE ID is used in a `gh issue list --search` query, which was flagged for potential shell injection. The CVE ID passes a strict `re.fullmatch(r"CVE-\d{4}-\d{4,7}")` validation in the upstream Python step before reaching the shell — no injectable characters survive. Safe as-is.
- **`.github/workflows/daily-draft.yml`:** `/tmp` file writes were flagged for potential cross-job contention. GitHub Actions runners are ephemeral and not shared between jobs — each job gets its own runner — so `/tmp` isn't shared with anything. Not a real exposure.

### Fixed (real CVE findings surfaced by OSV-Scanner)
- **`requirements-ci.txt`** — added explicit transitive pin `idna>=3.15` to close GHSA-65pc-fj4g-8rjx (DoS via domains with extremely large numbers of labels). pysigma's transitive chain was pulling in idna 3.9.0 which is vulnerable; the explicit pin forces the resolver to take the fixed version.
- **`osv-scanner.toml` added** — documented suppression of GHSA-w8v5-vhqr-4h9v (diskcache 5.6.3) with `ignoreUntil = 2026-09-07` (90-day re-review) and a written justification: no fix is published upstream, and pysigma's diskcache use in our CI context is local-only with no attacker-reachable input. Suppression will be revisited every Patch Tuesday until either a fix lands or the threat model changes.
- **`.github/workflows/osv-scan.yml`** — scan args now include `--config=osv-scanner.toml` so the suppression file is picked up automatically on every run.

### Added (full security pass — workflow failure notify, Patch Tuesday, Dependabot auto-merge, repo-health, settings runbook)
- **`.github/workflows/_notify-failure.yml` added (reusable)** — single shared workflow any CI job can call on failure to post a structured Discord embed. Wired into `lint.yml`, `secret-scan.yml`, `osv-scan.yml`, and `scorecard.yml` via the `notify-on-failure` job pattern with `if: failure() && github.event_name != 'pull_request'` (PR failures already surface on the PR; only push-to-main + scheduled failures ping Discord). Closes the silent-failure operational gap.
- **`.github/workflows/patch-tuesday.yml` added** — fires on the second Tuesday of every month at 14:00 UTC. Cron is `0 14 8-14 * 2` (Tuesday in days 8–14 of the month = second Tuesday by definition). Run-step gates on `date +%u`=2 and `date +%d` between 8 and 14 as a redundant check; workflow_dispatch bypasses the gate. Opens a tracking issue with MSRC + KEV review checklist and a hook to dispatch the Monday CVE lane for the month's high-impact CVEs. Idempotent — title-based dedup.
- **`.github/workflows/dependabot-auto-merge.yml` added** — auto-merges Dependabot PRs that are patch-only OR carry a security-advisory label, after CI green. Uses `pull_request_target` (justified with `# guard-allow` comment + zizmor suppression with full rationale in `.github/zizmor.yml`). **Bot-actor check hardened**: `github.event.pull_request.user.login == 'dependabot[bot]'` (immutable, set by GitHub) NOT `github.actor` (re-runnable to spoof). Repo-vars kill switch `AUTO_MERGE_DEPENDABOT=false`. The workflow does NOT check out PR code — it only calls gh-cli APIs against PR metadata.
- **`.github/workflows/repo-health.yml` added** — weekly drift assertion + on PR. Three checks:
  - Required files exist (`README.md`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/CODEOWNERS`, `.github/dependabot.yml`) → hard fail.
  - CODEOWNERS catch-all rule present → hard fail.
  - Every top-level directory has either an explicit CODEOWNERS rule OR falls through to the `*` catch-all → warn-only (a brand-new directory shouldn't immediately fail the build before the owner adds a rule).
  - CODEOWNERS rule format sanity — every non-comment line must contain `@<owner>` → hard fail.
- **`.github/dependabot.yml` extended** — grouped routine version-bumps so a normal Monday produces one PR per ecosystem instead of 5+. Security advisories still open their own dedicated PRs (Dependabot honors the `applies-to` distinction). `open-pull-requests-limit` raised from 5 to 10 for both github-actions and pip ecosystems to give the auto-merge workflow headroom on busy patch weeks.
- **`.github/allowed-actions.txt` extended** — `dependabot/fetch-metadata` added (used by the new dependabot-auto-merge workflow).
- **`.github/CODEOWNERS` extended** — explicit rules for `/docs/` and `/scripts/` so they don't fall through to the catch-all (closes the orphan check that repo-health would otherwise warn on).
- **`.github/zizmor.yml` extended** — suppresses `dangerous-triggers` on `dependabot-auto-merge.yml` with the full safety rationale (no PR code checkout, immutable bot author check, metadata-only API calls). Workflow-guard independently validates the `# guard-allow` comment.
- **`docs/github-settings.md` added** — the canonical runbook for settings that have to be enabled in the GitHub UI / API, not in a workflow file. 10 sections covering Code security & analysis (push protection, custom secret patterns, private vuln reporting), Rulesets (`main` + tag rulesets with the required-status-checks paste list), Actions settings (allowlist + workflow permissions defaults), Webhooks & integrations audit, Security advisories workflow, account-level (passkey, vigilant mode, PAT audit), notification routing, observability (security overview, autolinks), open TODOs (SHA-pin sweep, harden-runner block mode, custom secret patterns), quarterly review checklist. Pair this with the workflow CI surface — together they're the full hardening checklist.

### Added (operational workflows — KEV watcher + stale automation)
- **`.github/workflows/kev-watch.yml` added** — daily-scheduled job that diffs the CISA KEV catalog and opens a tracking issue when a newly-listed CVE matches our priority vendors (Microsoft, Fortinet, Cisco, Citrix, Ivanti, Palo Alto, SonicWall, VMware, F5, Progress/MOVEit, ConnectWise, Veeam, Atlassian) AND doesn't already have a write-up in `vulnerabilities/`. Idempotent — re-runs don't duplicate, and an existing open issue with the same title short-circuits. Opens at most one issue per run (highest-priority new entry only) to avoid spam if CISA does a batch add. Directly feeds the Monday CVE lane with prioritized work; the drafter now picks against a curated candidate instead of scanning the full feed cold.
- **`.github/workflows/stale.yml` added** — issue/PR staleness automation. Issues: 60d idle → `stale` label + comment; +14d → close. PRs decay faster (30d → stale, +7d → close) because the drafter opens new ones every weekday and a 30-day-old PR is almost always dead. Exemptions: anything labeled `pinned` / `security` / `needs-triage` / `in-progress` / `kev`, or anything with an assignee. Daily 02:15 UTC, off-peak. Operation budget of 30/run is enough for this repo's traffic.
- **`.github/allowed-actions.txt` updated** — comment notes `actions/stale` is now part of the actions/ owner-prefix allowlist.

### Added (security hardening pass — workflow-protecting + content-correctness CI)
- **`.github/workflows/workflow-guard.yml` added** — meta-CI that defends the CI surface against three GitHub Actions footguns no existing tool catches all of:
  - **New `pull_request_target` trigger** introduced without an explicit `# guard-allow: pull_request_target — <reason>` justification comment in the same workflow → hard fail. That trigger runs with write-access secrets on BASE-repo code while reviewing untrusted PR code; misuse is the canonical org-takeover footgun.
  - **New third-party action `uses:` line** introduced that isn't on the explicit allowlist (`.github/allowed-actions.txt`) → hard fail. Forces every new supply-chain dependency through deliberate review.
  - **New `github.event.*` template expansion** in any workflow change → warning annotation on the PR with line refs so it lands in the conversation, not just SARIF.
  - Runs only on PRs touching `.github/workflows/` or the allowlist file. Zero overhead on content PRs.
- **`.github/allowed-actions.txt` added** — canonical list of trusted action publishers (`actions/`, `github/codeql-action`, `step-security/harden-runner`, `anthropics/claude-code-action`, `ossf/scorecard-action`, `google/osv-scanner-action`, `DavidAnson/markdownlint-cli2-action`, `crate-ci/typos`, `lycheeverse/lychee-action`, `gitleaks/gitleaks-action`). Owner-prefix match — version / SHA pin can change without an allowlist update. Becomes the trusted-code manifest once the SHA-pin sweep lands.
- **`.github/workflows/content-correctness.yml` + `scripts/validate_content.py` added** — quality checks unique to a security-content publication that no existing lint job catches:
  - **MITRE ATT&CK technique IDs** referenced anywhere in the repo must exist in the current ATT&CK STIX bundle (fetched from `mitre-attack/attack-stix-data`, the live source — NOT the legacy `mitre/cti` mirror). Catches drafter hallucinations, typos, and silently-revoked techniques (ATT&CK v17 revoked `T1562.001` and `T1656`; both flagged and consciously allowlisted as historical Scattered Spider profile references).
  - **CVE filename ↔ body match** — every `vulnerabilities/CVE-YYYY-NNNNN.md` must reference its declared CVE ID at least once in the body. Catches copy-paste mistakes.
  - **Internal markdown links** — every `[label](relative/path)` must resolve to an existing file. Lychee handles external URLs; this closes the gap. Path-traversal-safe via `pathlib.resolve()` + `relative_to(REPO_ROOT)` check.
  - Runs on PRs that touch markdown / detections / vulnerabilities, on push to `main`, and weekly so deprecated ATT&CK IDs get caught even when our content doesn't change.

### Added (security hardening pass — secret scanning + dependency CVE scanning)
- **`.github/workflows/secret-scan.yml` added (gitleaks).** Catches first-party mistakes that the existing CI doesn't:
  - GitHub native secret scanning matches a fixed set of provider tokens. gitleaks adds generic-high-entropy + repo-specific patterns (Discord webhook URLs, Anthropic API keys `sk-ant-...`, Defender for Endpoint bearer tokens, Entra application client secrets).
  - PRs run a fast incremental scan; push-to-main + a weekly Monday cron run full-history scans.
  - Hardened identically to the other workflows (step-security/harden-runner audit, `persist-credentials: false`, minimal permissions, concurrency group).
- **`.gitleaks.toml` added.** Custom ruleset extends gitleaks' built-in default rules with four repo-specific patterns and a tight allowlist for template / placeholder files (Sigma + YARA templates, playbook examples, hardening template) so the false-positive rate stays at zero.
- **`.github/workflows/osv-scan.yml` added (OSV-Scanner).** Closes the dependency-monitoring gap:
  - `dependency-review` only fires on PRs that change the manifest. It doesn't flag existing vulnerable deps already on `main`.
  - `dependabot` only opens PRs when a newer version exists. It doesn't alert on "your pinned version has a known CVE with no fix yet".
  - OSV-Scanner scans `requirements-ci.txt` against OSV.dev (which aggregates GHSA, PyPA Advisory DB, OSV-Schema) and fails CI on any unfixed known CVE. SARIF uploaded to Code Scanning so findings land alongside CodeQL + Scorecard + gitleaks alerts.
  - Runs on PRs that touch `requirements*.txt` / `package*.json` / the workflow itself, on push to `main`, and weekly.

### Changed (security hardening pass — Anthropic credit graceful degradation)
- **`.github/workflows/daily-draft.yml` pre-flight credit check.** Before invoking the (long-running, expensive) `claude-code-action`, the workflow now makes a 1-token throwaway call to `api.anthropic.com/v1/messages` to verify the account has credit. Three outcomes:
  - **200 OK** → `have_credit=true`, the lane step runs as normal.
  - **`credit_balance` / `insufficient` / `quota` / `billing` in the error body** → `have_credit=false`, `skip_reason=insufficient_credit`. All lane steps and the fact-check step skip via `if:` gate. Workflow exits **green** (status: success) with a `::warning::` annotation pointing to https://console.anthropic.com/settings/billing. This is the explicit goal: when the API is out of budget, bypass and show green; resume normally when credit is topped up.
  - **Missing `ANTHROPIC_API_KEY` secret** → same green-skip behavior with `skip_reason=missing_secret`.
  - **Any other API error** (auth, network, malformed request) → fail hard. A real problem worth knowing about.
- **Cost of the pre-flight: ~1 input + 1 output token on Haiku** = roughly $4×10⁻⁷ per run. Effectively free.
- **Discord notify updated** to distinguish three outcomes: ✅ success (drafter ran end-to-end), ⏭️ skipped (pre-flight detected missing key or insufficient credit; explains the skip reason with the billing-console URL), ⚠️ failure (drafter ran but errored). Previously a credit-balance failure showed up as a generic "drafting run failed" red ping — now it's a yellow "skipped, top up here" ping that's actionable in one click.

### Changed (security hardening pass — additional findings)
- **`.gitignore` replaced.** The old file was a leftover C/C++ template with no relevance to this markdown+Python+YAML repo. New file blocks the actual detritus this stack produces: Python (`__pycache__`, `.pytest_cache`, virtual envs), Node (`node_modules` from `npx markdownlint-cli2`), editor/OS (`.vscode`, `.DS_Store`, `Thumbs.db`), local env (`.env`, `*.local`), CI artifacts (`zizmor.sarif`, `results.sarif`), plus the `.seo` / `.ot` / `.OT` extensions per maintainer request.
- **`requirements-ci.txt` added.** Python dependencies used by the CI workflows (pysigma, zizmor) were inline in the YAML — Dependabot couldn't monitor them. Now tracked in a real file at repo root with the same constraints. `lint.yml` updated to `pip install -r requirements-ci.txt` in both the sigma-validate and zizmor jobs.
- **`.github/dependabot.yml` extended.** Added the `pip` ecosystem to track `requirements-ci.txt`. Same weekly schedule as the existing github-actions ecosystem. Closes the gap where a pysigma or zizmor advisory could land without a Dependabot PR.
- **`.github/CODEOWNERS` extended.** Added explicit ownership rules for `/hardening/`, `/incident-reports/`, `/frameworks/`, and `/tools/` so they don't fall through to the catch-all `*` rule. Defense-in-depth — if you ever add other owners with limited paths, these content categories still require you.

### Verified — no fix needed
- **No hardcoded sensitive values** in `*.py`, `*.yml`, `*.toml`, `*.json` files. No IPs (other than expected GitHub / Microsoft / step-security infrastructure IPs in harden-runner audit logs), no contact emails, no API key / token / password patterns matching the standard scan regexes.
- **No `pull_request_target` usage** — the GHA security footgun. Only a comment reference in `lint.yml` documenting zizmor's check.
- **No Python script safety issues** — `subprocess` with `shell=True`, `eval`, `exec`, `os.system`, `yaml.load` (unsafe variant), `pickle.loads` all absent from `scripts/` and `detections/`.
- **No CI log secret leakage** — no `echo $SECRET` / `echo "${{ secrets.X }}"` patterns anywhere.
- **No tracked files that shouldn't be** — git ls-files clean for `.env`, `.key`, `.pem`, `secret`, `credential`, `.swp`, `.DS_Store`, `Thumbs.db`, `__pycache__`.
- **SECURITY.md is adequate** — GitHub Private Vulnerability Reporting + maintainer email both documented; no fix needed.

### Changed (security hardening pass — concurrency control)
- **`concurrency:` blocks added** to all seven hand-edited workflows (`lint.yml`, `daily-draft.yml`, `daily-reminder.yml`, `discord-reminder.yml`, `discord-todo-update.yml`, `scorecard.yml`, `todo-sync.yml`). `codeql.yml` skipped (GitHub-managed).
  - **`lint.yml`** uses `cancel-in-progress: true` — a new commit on a PR supersedes the previous in-flight CI run. Cuts wasted minutes on stale runs.
  - **All other workflows** use `cancel-in-progress: false` — scheduled / long-running, never killed mid-execution. A partial run is worse than waiting for the previous one to finish. Specifically protects the Tier-3 agentic drafter from being cancelled mid-Claude-session (which would burn API credit with no output).
  - Group key on every workflow is `${{ github.workflow }}-${{ github.ref }}` so concurrent runs are scoped per-branch (PR runs don't block `main` runs).

### Verified — no action needed
- **`${{ }}` interpolation audit** — no workflow interpolates user-controlled event payload (issue body, comment body, PR title, etc.) directly into a `run:` shell block. The only `github.event.*` reference is `github.event.inputs.lane` in `daily-draft.yml`, and it's assigned to an env var first (`LANE_INPUT: ${{ github.event.inputs.lane }}`) and only referenced as `$LANE_INPUT` from the shell. That's the canonical safe pattern.
- **Top-level `permissions:` blocks** — every hand-edited workflow has an explicit minimal-permissions block. `codeql.yml` has per-job permissions only (GitHub-managed). No `permissions: write-all` anywhere.
- **Zizmor** — clean at `--min-severity=medium` after the change (4 ignored, 37 suppressed — both numbers expected and tracked).

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
