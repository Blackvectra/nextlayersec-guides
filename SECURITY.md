# Security Policy

NextLayerSec Guides publishes detection content and incident-response playbooks. The "vulnerabilities" we care about here fall into two buckets:

1. **Repo security** — secrets accidentally committed, malicious content in a PR, broken / hijacked dependency in CI.
2. **Content safety** — a detection that would expose an environment if deployed as-written (e.g., an unsafe `bash`/`KQL` snippet, a rule that disables protections, or a playbook step that destroys evidence).

If you find either, please report it privately.

## Reporting a vulnerability

**Do not open a public issue or PR for security reports.**

- Preferred: GitHub **private vulnerability reporting** — `Security` tab → "Report a vulnerability" on this repo. Tracked alongside the code, encrypted at rest.
- Alternative: email the maintainer at the address in this repo's `git log` (`git log -1 --format='%ae'`).

Please include:

- A short description of the issue and where it lives (file path, line number).
- The impact you observed (or believe is possible).
- Steps to reproduce, or a proof of concept, if one exists.
- Your preferred credit name (or "anonymous").

## What to expect

| Stage | Target |
|------|--------|
| Acknowledgement | within 3 business days |
| Initial triage + severity | within 7 business days |
| Fix or mitigation plan | within 30 days (sooner for high-severity) |
| Public disclosure | coordinated; we'll cut a CHANGELOG entry and credit you |

## Scope

**In scope:**

- Secrets / tokens / keys checked into the repo.
- Malicious content in committed files (typo-squatted dependencies, hidden payloads in YAML/KQL/regex).
- Detection content that, when deployed verbatim, would create a security regression (disable controls, leak data, etc.).
- CI workflow misconfigurations that expand the repo's blast radius (overly broad `GITHUB_TOKEN` permissions, `pull_request_target` misuse, etc.).

**Out of scope:**

- Theoretical risk in the *documented techniques themselves* — this repo describes attacker tradecraft so defenders can detect it. Reporting "this playbook describes ransomware" is not a vulnerability report.
- Detection rule false positives or false negatives — file a normal issue or PR.
- Vulnerabilities in upstream tools we reference (file them with the vendor; we'll happily link to advisories from `vulnerabilities/`).

## Safe harbor

Good-faith research that complies with this policy will not be pursued by the project maintainers. Do not access data that isn't yours, do not run automated scanning that degrades availability for other users, and keep proof of concepts to the minimum needed to demonstrate the issue.

## Acknowledgements

A short list of reporters credited for past disclosures lives in `CHANGELOG.md` under the relevant release.
