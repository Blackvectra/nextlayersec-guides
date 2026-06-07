# Hardening — <Platform or Service>

- **Author:** <handle>
- **Last updated:** YYYY-MM-DD
- **Maturity:** published | validated | hardened
- **Scope:** what this baseline covers — and what it doesn't (link to sibling guides)
- **Prerequisites:** licensing, roles, baseline tenant config required before starting

## Why this matters

2–4 sentences. What attacks does this baseline prevent or significantly degrade? What's the realistic blast-radius reduction?

## The baseline

A numbered list of the policies / controls / configurations that make up the baseline. Each item:

1. **Name** — what you'd actually call it in the portal
   - **Purpose:** one sentence
   - **Scope (who/what):** users, devices, apps, conditions
   - **Control:** grant / block / require X
   - **Recommended setting:** specific values
   - **Test users / break-glass:** how to exclude an emergency account safely

## Rollout order

Some policies depend on others. Spell out the order, with rationale.

```text
1. Item A          (no dependencies, do first)
   ↓
2. Item B          (depends on A — won't work otherwise)
   ↓
3. Item C, D       (parallel — order doesn't matter between these)
   ↓
4. Item E          (riskiest — do after everything else and after user comms)
```

## Validation

How do you prove it's working?

- **Built-in tooling:** Conditional Access What-If, sign-in audit log filter, etc.
- **Synthetic test:** a specific action a test user can take that should be blocked/allowed
- **Detection signal:** which rule in `detections/` fires (or no longer fires) once the baseline is in place

## Common pitfalls

The 5–8 things people break the first time they roll this out. Be specific.

## Reversal plan

If this breaks production, how do you back out — fast and cleanly? Include the break-glass account assumption.

## Framework mapping

- **MITRE ATT&CK mitigations:** M1032 (Multi-Factor Authentication), M1018 (User Account Management), etc.
- **MITRE ATT&CK techniques addressed (prevented or significantly degraded):** T1078.004, T1110.003, etc.
- **NIST CSF 2.0:** PR.AA-01, PR.AA-04, etc.
- **ISO 27001:2022:** A.5.17, A.8.5, etc.
- **CIS Controls v8.1:** 5, 6

## References

- Vendor docs (Microsoft Learn / etc.)
- Microsoft Security Baselines (when applicable)
- CISA hardening guidance
- Related detections in this repo
- Related playbooks in this repo
