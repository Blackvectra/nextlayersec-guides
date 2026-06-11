# Getting help

Thanks for using NextLayerSec Guides. Here's where to go for which kind of help.

## I'm a SOC / defender using the content

- **A detection isn't firing the way I expected.** Read the `.md` sibling next to the `.kql` or `.yml` rule — the "Tuning" section covers the common environment-specific knobs. If it still doesn't fit, open an issue with the `detection` label, your fleet's data source (Defender XDR / Sentinel / Sysmon / Elastic / Splunk), and a sample row you wished had alerted.
- **A playbook step doesn't match my tooling.** Playbooks target a Microsoft 365 / Entra ID + Defender for Endpoint stack. If you're on AWS / GCP / Okta, the shape transfers but the surfaces differ — open a discussion with the equivalent surface in your environment and I'll add a cross-mapping note.
- **A hardening baseline item conflicts with vendor guidance.** Read the "Reversal plan" section in the matching `hardening/*.md` first — most conflicts dissolve when you see the trade-off documented. If there's a genuine conflict with a current vendor doc, open an issue with the specific vendor URL and the specific baseline item.

## I want to contribute content

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the structural template and CI requirements.
- For new detections, copy `detections/kql/_template.kql` and `detections/sigma/_template.yml` and follow the most recent shipped file as the style guide (T1218.011, T1021.001).
- For new playbooks, copy `blue-team-playbooks/_template.md`.
- For new hardening guides, copy `hardening/_template.md`.

## I found a security issue

**Do not open a public issue or PR.** Read [`SECURITY.md`](SECURITY.md) and use GitHub's Private Vulnerability Reporting in the Security tab. SLA: 3 business days for acknowledgement, 7 for triage, 30 for fix.

## I want to ask a general question

Use the **Discussions** tab. Anything that's not a bug, security issue, or content contribution belongs there.

## I want to keep up with what's new

- **CHANGELOG.md** — every shipped change is documented there with a "Week of YYYY-MM-DD" subsection.
- **README badges** — top of `README.md`. Green = CI clean.
- **OpenSSF Scorecard** — the OpenSSF badge in `README.md` rolls up the security posture in a single number.

## Where this project does NOT help

- Vendor-product configuration step-by-step beyond what's in the hardening guides — for that, you want Microsoft Learn / Cisco Live / Palo Alto Live Community.
- Generic "is this a real attack?" triage of individual log lines — you want your SIEM vendor's support or a hired incident responder.
- Compliance-document templates — there are vendors who sell those; we focus on the technical baseline.
