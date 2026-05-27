# Playbook: <Scenario name>

- **Author:** <handle>
- **Last updated:** YYYY-MM-DD
- **Severity default:** Low | Medium | High | Critical
- **Owner role:** SOC Tier 1 | Tier 2 | IR Lead

## Trigger
What alert, ticket, or signal kicks this off (link to detection rule(s) in `detections/`).

## Scope
What this playbook covers — and what it doesn't (point to sibling playbooks).

## Triage (first 15 minutes)
1. Validate the alert is not a known FP.
2. Capture initial artifacts: host, user, time, source IP, process tree.
3. Decide severity and escalate if needed.

## Containment
- Network: isolate host (EDR isolation, NAC quarantine VLAN).
- Identity: disable / force password reset / revoke sessions.
- Endpoint: block hash / kill process / take memory dump.

## Eradication
- Remove persistence (services, scheduled tasks, run keys, WMI subs).
- Patch / reconfigure root cause.
- Rotate credentials and secrets the attacker could have touched.

## Recovery
- Reimage or restore from known-good backup.
- Re-enable account with MFA enforced.
- Monitor for re-infection (heightened alerting for N days).

## Lessons learned
- What worked, what didn't.
- Detection gaps → file an issue / new detection.
- Update this playbook.

## Framework mapping
- **MITRE ATT&CK:** T<id>(s)
- **NIST CSF:** Respond → RS.RP / RS.AN / RS.MI
- **NIST SP 800-61r2 phase:** Detection & Analysis → Containment / Eradication / Recovery → Post-Incident
- **ISO 27001:** A.5.24 – A.5.27 (Information security incident management)

## References
- Detection rules: `detections/...`
- Related playbooks: `blue-team-playbooks/...`
- Vendor docs / blog posts
