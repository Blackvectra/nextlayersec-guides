# GitHub repo security settings runbook

Settings that have to be enabled in the GitHub UI / API, not in a workflow
file. This is the canonical checklist — every box ticked here is a control
that no `.github/workflows/*.yml` can substitute for.

Order matters: top items are the highest leverage and lowest friction.
Walk top-down on first setup; revisit quarterly.

---

## 1. Code security and analysis (Settings → Code security and analysis)

| Setting | Action | Why |
|---|---|---|
| **Dependency graph** | Enable | Free on public repos. Powers Dependabot + dependency-review. |
| **Dependabot alerts** | Enable | Surface CVEs in any dependency. |
| **Dependabot security updates** | Enable | Auto-PR when a vulnerable dep has a fix. Pairs with `.github/workflows/dependabot-auto-merge.yml`. |
| **Dependabot version updates** | Enable | Configured in `.github/dependabot.yml` — already done. |
| **Secret scanning** | Enable | Free on public repos. Provider-token detection. |
| **Secret scanning push protection** | **Enable — one-click, do this first** | Blocks pushes containing detected secrets *before* they hit the remote. Complements gitleaks (which catches things in CI after the push). |
| **Validity checks** (where available) | Enable | GitHub auto-tests detected tokens against the issuing provider. Reduces false positives in alerts. |
| **Custom secret scanning patterns** | Mirror `.gitleaks.toml` | Add the same patterns to GitHub-native scanner so findings appear in the Security tab too, not just CI logs. Today that's `defender-mde-bearer`, `anthropic-api-key`, `discord-webhook`. |
| **Private vulnerability reporting** | Enable | Lets researchers report privately via the Security tab. Your `SECURITY.md` already documents this path. |
| **CodeQL** | Already on (default setup) | Don't switch to advanced setup without a reason — default setup auto-updates. |

---

## 2. Rulesets (Settings → Rules → Rulesets)

A `main` branch ruleset enforces protections that branch protection rules
historically did, but with more granular controls.

### Required settings on the `main` ruleset

| Control | Setting | Notes |
|---|---|---|
| Restrict creations | On | No one creates a branch named `main` other than the existing one. |
| Restrict updates | On (with bypass: maintainer) | Direct pushes blocked; PR-only. |
| Restrict deletions | On | `main` cannot be deleted. |
| Require linear history | On | No merge commits. Squash-merge or rebase-merge only. |
| Require pull request before merge | On | 0 required approvers (solo-maintained); else the auto-drafter blocks itself. |
| Require status checks | On — list below | These must pass before merge. |
| Block force pushes | On | Closes the `git push --force` accident vector. |
| Require signed commits | On (after GPG/Sigstore setup) | Ties every commit to a verified identity. Friction on first commit; long-term high-value. |
| Require code scanning results | On — block on high | CodeQL + Scorecard + gitleaks + OSV all upload SARIF. Block merge if any has new high-severity. |

### Required status checks (paste into the ruleset)

```text
markdownlint
sigma-validate
yara-validate
typos
linkcheck
zizmor
dependency-review
gitleaks
OSV scan
guard
validate
CodeQL
```

### Tag ruleset

Create a separate ruleset for `v*` tags:
- Restrict creations: maintainer-only.
- Restrict deletions: on.
- Restrict updates: on (no tag re-pointing).

This prevents tag squatting / forced re-pointing if you ever cut releases.

---

## 3. Actions (Settings → Actions → General)

| Setting | Value | Why |
|---|---|---|
| Allow actions and reusable workflows | **Allow select actions** | Default of "all actions" is too broad. |
| Allow actions created by GitHub | On | `actions/*`, `github/*`. |
| Allow actions by Marketplace verified creators | On | Catches the verified-publisher pool. |
| Allow specified actions and reusable workflows | Add the explicit allowlist below | Mirror of `.github/allowed-actions.txt`. |
| Fork pull request workflows from outside collaborators | **Require approval for all outside collaborators** | First-time and one-off contributors must be approved before their PR triggers any workflow run. |
| Workflow permissions (default `GITHUB_TOKEN`) | **Read repository contents and packages permissions** | Per-workflow elevation only. Catches any future workflow that forgets its own `permissions:` block. |
| Allow GitHub Actions to create and approve pull requests | **Off** | The drafter creates PRs via the `gh` CLI with `GITHUB_TOKEN`, not via the `pull-requests` workflow permission. Leave off. |

### Allowed actions paste-list (Settings → Actions → General → "Allow specified actions")

```text
DavidAnson/markdownlint-cli2-action@*,
crate-ci/typos@*,
lycheeverse/lychee-action@*,
gitleaks/gitleaks-action@*,
google/osv-scanner-action/*@*,
anthropics/claude-code-action@*,
ossf/scorecard-action@*,
step-security/harden-runner@*,
dependabot/fetch-metadata@*,
```

`actions/*` and `github/*` are covered by the "GitHub-created" toggle.

---

## 4. Webhooks + integrations audit (Settings → Webhooks / Integrations)

Quarterly review:

- [ ] **Webhooks**: every URL accounted for. Discord webhook is yours; anything else is a red flag.
- [ ] **Installed GitHub Apps**: anything you don't recognize gets revoked. Dependabot + step-security/secure-repo are expected.
- [ ] **OAuth app access** (Settings → Applications → Authorized OAuth Apps on your **account**): revoke anything stale.
- [ ] **Deploy keys**: should be zero on this repo.
- [ ] **Codespaces secrets** (separate from Actions secrets): usually empty, verify.
- [ ] **Environments + protection rules**: none yet. Add `production` with required reviewer if you ever publish tagged releases.

---

## 5. Repository security advisories (Security tab → Advisories)

Workflow for first-party findings:

1. Draft an advisory in the Security tab BEFORE the CHANGELOG entry.
2. Request a GitHub-assigned CVE ID (if applicable to a published detection).
3. Coordinate disclosure with anyone who's vendored your detections.
4. Publish; the public CHANGELOG entry references the GHSA-XXXX ID.

---

## 6. Account-level (your personal account, not the repo)

The keys to the kingdom:

| Setting | Action |
|---|---|
| 2FA method | **Passkey / WebAuthn** — same standard you mandate for client tenants. Replace TOTP/SMS. |
| Vigilant mode | Settings → SSH and GPG keys → "Flag unsigned commits as unverified". |
| Personal access token audit | Revoke all classic PATs. Migrate to fine-grained tokens scoped to `Blackvectra/nextlayersec-guides` only, 90-day expiry. |
| Session + SSH key review | Settings → Sessions / SSH keys → revoke anything older than rotation policy. |
| Recovery codes | Store offline (1Password / paper in safe). Only fallback if a passkey ever fails. |

---

## 7. Notification routing (Settings → Notifications)

The signal drowns in the noise without routing:

- **Mobile push**: high-severity Dependabot + secret scanning + code scanning.
- **Email digest**: everything else.
- **Watch level on `nextlayersec-incidents`** (private repo): **All activity** — small repo, every event matters.

---

## 8. Discoverability / observability

| Item | Action |
|---|---|
| Security tab → **Security overview** | Enable. Single pane of glass for CodeQL + Scorecard + Dependabot + gitleaks + OSV findings. |
| Settings → Autolinks | Map `CVE-#` → NVD, `T####` → MITRE ATT&CK, `GHSA-#` → GHSA. Makes every reference clickable in issues/PRs. |
| Settings → Moderation → Interaction limits | Keep off in normal operation. Panic button for issue-spam waves. |

---

## 9. Open TODOs that need this runbook before they can be closed

- **SHA-pin all third-party Actions.** Use Pinact or `ratchet pin` to convert every `@v#` tag pin to a 40-char commit SHA + comment with the tag for human readability. Dependabot keeps SHA pins current automatically once configured. Order: (1) actions with write permissions first — `anthropics/claude-code-action`, `github/codeql-action/*`, `gitleaks/gitleaks-action`. (2) Then the rest.
- **Promote `harden-runner` to `block` mode.** Today every workflow runs with `egress-policy: audit`. After one week of clean audit data, build an allowlist of legitimate endpoints (npmjs, pypi, github.com, api.cisa.gov, discord.com, raw.githubusercontent.com, etc.) and switch to `egress-policy: block` per workflow. Catches a compromised dependency exfiltrating to a malicious endpoint.
- **Configure custom GitHub-native secret scanning patterns.** Mirror the four patterns in `.gitleaks.toml` into Settings → Code security → Secret scanning → Custom patterns. Makes findings appear in the Security tab.

---

## 10. Quarterly review checklist

Walk through items 1–8 every 90 days:

- [ ] Verify push protection is still on.
- [ ] Verify the `main` ruleset's required-status-checks list still matches the workflow inventory in `.github/workflows/`.
- [ ] Audit installed GitHub Apps + webhooks (item 4).
- [ ] Re-verify allowed-actions list matches actually-used actions (diff against `grep -rhE '^\s*-?\s*uses:' .github/workflows/`).
- [ ] Rotate personal access tokens if any have expired.
- [ ] Check Insights → Traffic for anomalous clone/view spikes.

Tracked as a quarterly reminder issue (use the same Patch Tuesday workflow
template — schedule for the first Monday of January / April / July / October).
