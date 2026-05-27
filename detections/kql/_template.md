# <Detection Title>

- **Query file:** `<name>.kql`
- **Author:** <handle>
- **Last updated:** YYYY-MM-DD
- **Status:** experimental | testing | production
- **Severity:** Low | Medium | High | Critical

## What it detects
One or two sentences describing the behavior and why it matters.

## ATT&CK mapping
- **Tactic:** e.g., Execution
- **Technique:** T<id> – <name>
- **Sub-technique:** T<id>.<sub>

## Data sources
- Table(s): `DeviceProcessEvents`, `SecurityEvent`, etc.
- Required connectors: Defender for Endpoint, Windows Security Events via AMA, etc.
- Minimum retention recommended: 30 days

## Logic
Explain the query plain-English: what fields, what filters, what window.

## False positives
- Known admin tooling (e.g., SCCM, Intune scripts)
- Vendor agents that legitimately use the technique
- How to suppress (allowlist host / account / parent process)

## Tuning
- Adjust `lookback`, thresholds, or excluded accounts.
- Consider joining with `IdentityInfo` to filter service accounts.

## Response
Link to the relevant playbook in `blue-team-playbooks/` once an alert fires.

## References
- Upstream rule (if adapted): URL
- Microsoft docs / blog posts
- Related CVE in `vulnerabilities/`
