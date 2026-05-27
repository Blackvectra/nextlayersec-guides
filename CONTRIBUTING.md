# Contributing

Thanks for adding to NextLayerSec Guides. The repo is opinionated about structure so it stays usable as it grows.

## Branching

- `main` is always shippable.
- Branch from `main` using `add/<topic>` or `fix/<topic>`.
- Open a PR (draft is fine) and link the relevant `TODO.md` line if applicable.

## Where to add what

| Adding… | Goes in | Template |
|---------|---------|----------|
| New CVE write-up | `vulnerabilities/CVE-YYYY-NNNNN.md` | `vulnerabilities/template.md` |
| KQL detection | `detections/kql/T<id>_<name>.kql` + `.md` | `detections/kql/_template.*` |
| Sigma rule | `detections/sigma/T<id>_<name>.yml` | `detections/sigma/_template.yml` |
| YARA rule | `detections/yara/<family>.yar` + `.md` | `detections/yara/_template.yar` |
| Splunk search | `detections/splunk/T<id>_<name>.spl` + `.md` | `detections/splunk/_template.spl` |
| IR playbook | `blue-team-playbooks/<scenario>.md` | `blue-team-playbooks/_template.md` |
| Detection workflow | `detection-workflows/<alert-family>.md` | `detection-workflows/_template.md` |
| Purple-team lab | `purple-team-labs/<name>/` | `purple-team-labs/_template/` |
| Threat actor / campaign / TTP | `threat-intelligence/{actors,campaigns,ttps}/<name>.md` | `threat-intelligence/.../_template.md` |

## Style

- Markdown only (no HTML unless necessary).
- Wrap lines naturally — no hard wrap at 80.
- Use ATX headers (`#`, `##`, …) and fenced code blocks with a language tag.
- File names use `kebab-case.md` except where a convention exists (`CVE-YYYY-NNNNN.md`, `T<id>_<name>.kql`).
- Every detection has a markdown sibling.
- Map everything to MITRE ATT&CK technique IDs.
- Cite primary sources — vendor blogs, CISA, MITRE, Microsoft Learn.

## Checks

CI runs:

- `markdownlint` against `**/*.md`
- `lychee` link checker against `**/*.md`

Run locally before pushing:

```bash
npx markdownlint-cli2 "**/*.md"
docker run --rm -v "$PWD":/work lycheeverse/lychee --offline /work
```

## Commit messages

Short imperative subject line, e.g.:

```
add KQL detection for T1059.001 encoded PowerShell
add playbook for phishing email triage
fix broken link in nist-csf.md
```

## Sensitive content

- **Never commit malware samples.** Reference by SHA-256 only.
- **Never commit customer / production data.** Use synthetic examples.
- **Never commit secrets, tokens, or API keys.**

## License

By contributing you agree your contributions are released under the same license as the repository.
