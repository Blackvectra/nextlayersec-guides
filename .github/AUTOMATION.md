# Automation

Three scheduled workflows keep the repo moving. All three are also runnable on
demand from the **Actions** tab via **Run workflow**.

| Workflow | File | What it does | When |
|----------|------|--------------|------|
| Issue reminder | `daily-reminder.yml` | Opens a `daily-reminder`-labeled GitHub issue with the day's lane + checklist, assigned to you. | Daily 13:00 UTC |
| Discord reminder (Tier 2) | `discord-reminder.yml` | Posts the day's focus to Discord. On CVE day it pulls the newest CISA KEV additions not yet in the repo; on detection day it suggests an uncovered ATT&CK technique. | Daily 13:00 UTC |
| **Daily draft (Tier 3, all 7 days)** | `daily-draft.yml` | Runs Claude Code headlessly every day to **draft** the day's lane content (Mon CVE, Tue detection, Wed playbook, Thu threat intel, Fri tools, Sat repo hygiene, Sun weekly review) and open a **draft PR** for review. Pings Discord when done. | Daily 13:30 UTC |
| TODO auto-sync | `todo-sync.yml` | Regenerates the `BEGIN AUTO`-marked sections of `TODO.md` from what's on disk. Commits the update on pushes to `main`; fails PRs whose TODO is stale. | Push to `main` / PRs touching content / manual |

> Times are UTC. 13:00 UTC = 8:00 AM CDT / 7:00 AM CST. GitHub Actions cron does
> not auto-adjust for daylight saving — nudge the cron by one hour in winter if
> you care about the exact local time.

## Required secrets

Add these under **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Used by | How to get it |
|--------|---------|---------------|
| `DISCORD_WEBHOOK_URL` | Tier 2 + Tier 3 | In Discord: **Server Settings → Integrations → Webhooks → New Webhook**, choose the channel, **Copy Webhook URL**. |
| `ANTHROPIC_API_KEY` | Tier 3 only | From the Anthropic Console (`console.anthropic.com`) → API keys. |

If a secret is missing, the relevant workflow logs a warning and skips that step
rather than failing — so you can enable Tier 2 today and add Tier 3 later.

## Testing it

1. Add `DISCORD_WEBHOOK_URL`, then go to **Actions → Discord daily reminder →
   Run workflow**. You should get a message in your channel within a few seconds.
2. For Tier 3: add `ANTHROPIC_API_KEY`, then **Actions → Daily draft → Run
   workflow** and set the `lane` input to `cve` or `detection` to force a run on
   any day. Watch it open a draft PR.

## Cost & safety notes

- **Tier 2 is free** — it only calls public feeds and the Discord webhook.
- **Tier 3 costs a small amount per run** (one Claude Code drafter + one fact-checker on `claude-sonnet-4-6`, capped). Fires daily.
- **Auto-merge with fact-check gate.** After each lane drafts a PR, two more steps run inside the same workflow:
  1. **Regex precheck** — rejects on any `TBD — verify`, `FIXME`, `XXX`, or `????` marker in the diff.
  2. **Adversarial Claude fact-check** — independent skeptic-role review. Verifies CVE IDs against KEV, MITRE technique IDs, KQL/Sigma syntax, cross-references, and that factual claims have citations. Writes its verdict to `/tmp/fact-check-verdict.txt`.
  3. If both pass, the PR is marked ready and **GitHub native auto-merge** is enabled (`--auto --squash --delete-branch`). The merge only happens once every required CI check (`markdownlint`, `linkcheck`, `sigma-validate`, `todo-sync`) passes.
  4. If either fails, the PR stays a draft, gets a `needs-review` label, and a comment with the failure reasons is posted.
- **Kill switch.** Set repo variable `AUTO_MERGE_ENABLED=false` (Settings → Secrets and variables → Actions → Variables) to keep the fact-check running but skip the auto-merge step. PR is marked ready; you merge manually.
- **Branch protection recommended.** For the strongest gate, add a branch-protection rule on `main` requiring `markdownlint`, `linkcheck`, `sigma-validate`, and `todo-sync` as required status checks. Without that, auto-merge respects only GitHub's default checks.
- GitHub security policy: PRs opened by the Actions bot do **not** automatically trigger downstream workflows that fire on `pull_request` events. The fact-check + auto-merge run **inside the same workflow run** as the drafter, so this doesn't matter for the auto-merge path. The lint workflow itself triggers on `push`, so it does run.

## Tuning

- **Change the cadence / lanes:** the lane logic lives in each workflow's
  weekday `case` block (and the `lanes` table in `daily-reminder.yml`).
- **Change the model or turn cap:** edit `claude_args` in `daily-draft.yml`.
- **Disable a workflow:** Actions tab → select the workflow → **⋯ → Disable
  workflow** (no code change needed).
