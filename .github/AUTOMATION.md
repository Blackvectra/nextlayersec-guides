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
- **Tier 3 costs a small amount per run** (one Claude Code session on
  `claude-sonnet-4-6`, capped at `--max-turns 25`). It only runs twice a week on
  schedule.
- Tier 3 **never merges anything** — it opens *draft* PRs. The prompts instruct
  Claude to mark unverified facts as "TBD — verify" and to list them in the PR
  body, so you always review before merge.
- GitHub security policy: PRs opened by the Actions bot do **not** automatically
  trigger the `lint.yml` checks. Either push an empty commit, or close/reopen the
  PR, to kick CI on a Tier 3 draft.

## Tuning

- **Change the cadence / lanes:** the lane logic lives in each workflow's
  weekday `case` block (and the `lanes` table in `daily-reminder.yml`).
- **Change the model or turn cap:** edit `claude_args` in `daily-draft.yml`.
- **Disable a workflow:** Actions tab → select the workflow → **⋯ → Disable
  workflow** (no code change needed).
