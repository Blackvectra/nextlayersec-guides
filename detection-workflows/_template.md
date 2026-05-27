# Detection Workflow: <Alert family>

- **Author:** <handle>
- **Last updated:** YYYY-MM-DD
- **Tier:** SOC Tier 1 / Tier 2

## Trigger
Alert(s), detection rule(s), or hunt query that produces this case. Link to `detections/`.

## Initial questions (≤ 5 min)
- Who? (user / host)
- What? (process / command / URL / file)
- When? (time, frequency)
- Where? (network segment / cloud workload)
- Why suspicious? (which signal matched)

## Pivot points
- Process tree (parent / child / sibling)
- Network connections during the window
- Identity context: account type, MFA status, recent risk events
- File reputation / hash lookups

## Decision tree
1. If <indicator> → escalate to playbook `X`.
2. If <benign condition> → close as FP, add suppression rule.
3. If unclear → escalate to Tier 2 with collected artifacts.

## Artifacts to collect
- Raw event(s)
- Process tree screenshot
- Hash + VT / MalwareBazaar link
- Network connection summary

## Escalation criteria
When to page IR, when to engage the on-call, when to invoke comms / legal.

## References
- Related playbook(s): `blue-team-playbooks/...`
- Related detection(s): `detections/...`
- MITRE ATT&CK technique(s)
