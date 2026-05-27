# Lab: <Technique name>

- **Technique:** T<id> – <name>
- **Author:** <handle>
- **Last updated:** YYYY-MM-DD
- **Environment:** isolated test VM / lab tenant only — never run on production

## Objective
What we are emulating and what detections / playbooks we are validating.

## Expected detections
- `detections/kql/T<id>_<name>.kql`
- `detections/sigma/T<id>_<name>.yml`

## Expected playbook response
- `blue-team-playbooks/<playbook>.md`

## Files
- `emulation.md` — exact commands to run
- `results.md` — captured outcome and gap list
