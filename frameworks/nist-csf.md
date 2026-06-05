# NIST Cybersecurity Framework (CSF) 2.0

> Updated for **CSF 2.0** (NIST CSWP 29, February 2024). The major change from 1.1: a new sixth Function — **Govern** — wraps risk strategy and oversight around the original five (Identify / Protect / Detect / Respond / Recover). This page reflects 2.0 throughout.

## What it is

The NIST Cybersecurity Framework is a voluntary, outcome-based framework for understanding, managing, and reducing cybersecurity risk. It organizes work into six core Functions, each broken into Categories and Subcategories (concrete outcomes). It does not prescribe controls — it tells you the *what* and lets you pick the *how* (which is why it pairs cleanly with ISO 27001, CIS Controls, NIST SP 800-53, etc.).

## Why it matters (for a SOC / MSP)

- **Universal language** for talking to executives, auditors, insurers, and engineers at the same time.
- **Risk-based prioritization** instead of compliance-checklist theater.
- **Scalable** — same Functions work for a 20-seat client and an enterprise.
- **CMMC, FedRAMP, HIPAA, PCI, SOC 2** all map back to CSF outcomes; pick CSF as your spine and the rest are crosswalks.
- **Cyber insurance carriers increasingly ask for CSF posture** in renewal questionnaires. A pre-built CSF profile shortens those conversations from days to hours.

## The six Functions (CSF 2.0)

| Function | Two-line summary |
|----------|------------------|
| **Govern (GV)** | *New in 2.0.* The strategy, policies, risk appetite, roles, and oversight that wrap around everything else. Owns the answers to "who decides," "what's our risk tolerance," and "how do we know we're aligned with the business." |
| **Identify (ID)** | Know your assets, data, people, suppliers, vulnerabilities, and business context. You can't protect what you don't know exists. |
| **Protect (PR)** | Controls that prevent or limit incidents — identity, access, awareness, data security, platform security, technology infrastructure. |
| **Detect (DE)** | Continuous monitoring and analysis that surfaces adverse events fast. Where the SOC mostly lives. |
| **Respond (RS)** | What happens when something fires — analysis, containment, mitigation, communication, reporting. |
| **Recover (RC)** | Restoring services, validating integrity, capturing lessons, communicating recovery status. |

### What changed from 1.1 → 2.0

- **New Function:** Govern (`GV.*`). Sub-categories cover Org Context, Risk Management Strategy, Roles & Responsibilities, Policy, Oversight, Cyber Supply Chain Risk.
- **Cybersecurity Supply Chain Risk Management** (`GV.SC`) elevated as its own Category — third-party risk is now first-class.
- **Reorganized Subcategories** — many 1.1 outcomes moved or were merged. If you have a 1.1 profile, NIST publishes an official 1.1 → 2.0 crosswalk.
- **Tiers** (Partial / Risk Informed / Repeatable / Adaptive) and **Profiles** (Current / Target) carry over from 1.1 with clearer guidance.
- **Implementation Examples** now ship with the framework — concrete, technology-neutral example actions per Subcategory.

## How to use this in a SOC / MSP engagement

### Week 1 — kickoff

1. **Pick a scope.** The whole client, one business unit, one cloud tenant — whatever you can finish a profile for in two weeks. Premature scope creep is the #1 reason CSF projects stall.
2. **Run a Current Profile workshop** (2 hours). For each of the 6 Functions, walk 4–8 Subcategories with the client and score:
    - `Partial` — ad hoc, undocumented, person-dependent
    - `Risk Informed` — informed by risk, documented but inconsistent
    - `Repeatable` — formal, repeatable, measured
    - `Adaptive` — continuously improved, integrated with business

    Don't try to score every Subcategory in CSF — pick the 30–40 that matter most for this client's threat model. NIST's "Core Profile" downloads make a good starting list.
3. **Define a Target Profile.** Where does the client *need* to be in 12 months given their industry, regulators, customers, and insurance posture? Aim for one Tier up from Current on the highest-risk Subcategories — don't try to leapfrog two Tiers across the board.
4. **Identify the gap list.** Subtract Current from Target. The remaining items are the roadmap. Order by (risk reduction) ÷ (effort).

### Week 2–4 — build the roadmap

Group the gap list into 30-day, 90-day, and 12-month buckets. For each gap, attach:

- **Owning Function + Subcategory** (e.g., `DE.CM-09 Computing hardware and software, runtime environments, and their data are monitored`)
- **Owner** (named person at the client)
- **Acceptance criteria** (what "done" looks like — link to a control, a detection, a policy doc)
- **Effort estimate** (S/M/L)
- **Cost** if applicable
- **Risk reduced if completed** (high / medium / low)

A 50-line spreadsheet beats a 50-page CSF report every time.

### Ongoing — operationalize

- **Weekly** in your SOC tooling: tag each new detection rule with its CSF Subcategory (e.g., a phishing detection tags `DE.CM-09` and `DE.AE-02`). Tag each playbook with `RS.MA-*` / `RS.AN-*`. This lets you produce a "CSF coverage heatmap" any time the client asks for one. The [`COVERAGE.md`](../COVERAGE.md) file in this repo already does the equivalent for MITRE ATT&CK — CSF tagging is the executive-side counterpart.
- **Quarterly** with the client: re-score 5–10 Subcategories the roadmap touched. Show movement. Adjust Target if the threat landscape moved (e.g., a new ransomware family in their sector raises `DE.AE` priority).
- **Annually** for the insurance renewal / audit: regenerate the Current Profile from the year's evidence, walk through it with the client's exec sponsor, set next year's Target.

## How the repo content maps to CSF 2.0

Use this as a quick crosswalk when tagging detections / playbooks / threat intel for a client's CSF roadmap.

### Govern (GV)

- `GV.OC` Organizational Context — covered indirectly by the [`frameworks/`](.) crosswalks (SOC 2 / ISO 27001 / IRS Pub 1075).
- `GV.SC` Cybersecurity Supply Chain Risk — see `.github/dependabot.yml` and the OpenSSF Scorecard workflow for a worked supply-chain example.

### Identify (ID)

- `ID.AM` Asset Management — every detection in [`detections/`](../detections/) implicitly assumes an asset inventory; the [`detections/DATA_SOURCES.md`](../detections/DATA_SOURCES.md) matrix says what telemetry each rule depends on.
- `ID.RA` Risk Assessment — the [`vulnerabilities/`](../vulnerabilities/) CVE library and its CISA-KEV-first selection criteria.

### Protect (PR)

- `PR.AA` Identity & Access Management — the Identity & Cloud Attack section of [`tools/blue-team-tools.md`](../tools/blue-team-tools.md).
- `PR.AT` Awareness & Training — the user-reporting loop documented in the [phishing-email-triage playbook](../blue-team-playbooks/phishing-email-triage.md).

### Detect (DE)

- `DE.CM-*` Security Continuous Monitoring — **the SOC's home Function**. Every rule in [`detections/`](../detections/) maps here. The [`COVERAGE.md`](../COVERAGE.md) matrix is your evidence.
- `DE.AE-*` Adverse Event Analysis — the detection workflows in [`detection-workflows/`](../detection-workflows/).

### Respond (RS)

- `RS.MA` Incident Management — the playbooks in [`blue-team-playbooks/`](../blue-team-playbooks/), starting with [phishing-email-triage](../blue-team-playbooks/phishing-email-triage.md) and [ransomware-outbreak](../blue-team-playbooks/ransomware-outbreak.md).
- `RS.AN` Incident Analysis — [`detection-workflows/`](../detection-workflows/).
- `RS.CO` Incident Communication — each playbook's "Lessons Learned" + comms checklist sections.
- `RS.MI` Incident Mitigation — the containment sections of each playbook.

### Recover (RC)

- `RC.RP` Incident Recovery Plan Execution — the recovery sections of each playbook.
- `RC.CO` Incident Recovery Communication — public / customer-facing comms outside this repo, but referenced in the ransomware playbook.

## Worked example: phishing incident through CSF 2.0

A user reports a phish. Here's how the response touches every Function:

| Phase | Function | Subcategory | What you did | Repo reference |
|-------|----------|-------------|--------------|----------------|
| Detection | **Detect** | `DE.CM-09` | Defender for Office 365 + PAB reporting | [`T1566.001` detection](../detections/kql/T1566.001_attachment-link-credential-harvester.md) |
| Triage | **Detect** | `DE.AE-02` | Pull headers, hash payload, sandbox URL | [phishing-email-triage playbook](../blue-team-playbooks/phishing-email-triage.md) |
| Identify scope | **Identify** | `ID.RA-03` | EmailEvents hunt for delivered count | playbook hunt queries |
| Contain | **Respond** | `RS.MI-01` | TABL block, Threat Explorer purge | playbook containment section |
| Identity follow-up | **Respond** | `RS.MI-02` | Revoke sessions, force password + MFA | playbook + [`T1078.004` detection](../detections/kql/T1078.004_risky-signin-mailbox-rule.md) |
| Comms | **Respond** | `RS.CO-02` | Notify impersonated org, internal users | playbook comms checklist |
| Recover access | **Recover** | `RC.RP-01` | Re-enable account on a clean device | playbook recovery section |
| Update controls | **Protect** | `PR.AA-01` | Add protected-domain entry in MDO | playbook lessons-learned |
| Document for board | **Govern** | `GV.OV-03` | Update CSF Current Profile with one-cell delta | client deliverable |

That's a single 90-minute incident producing artifacts that touch **every Function**. The CSF profile becomes a living document, not a quarterly snapshot.

## Common CSF mistakes (and how to avoid them)

1. **Scoring every Subcategory.** You don't need to. Pick the 30–40 that matter for this client's threat model.
2. **Treating it as compliance.** CSF is *risk-based*, not controls-checklist. If a control is "implemented" but doesn't reduce the risk it's mapped to, the score doesn't go up.
3. **Skipping Govern.** It's new and feels meta. Skip it and you'll discover your roadmap has no executive sponsor at month 4.
4. **Letting the Target Profile drift.** Reset it annually with the exec sponsor. Threat landscape moves; so should your Target.
5. **Confusing Profile with Tier.** Profile = "what outcomes do I have." Tier = "how mature is my process around them." Both are useful; they answer different questions.

## References

- **NIST CSF 2.0 specification:** <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf>
- **CSF 2.0 official landing page** (Profiles, Tools, Quick Start Guides): <https://www.nist.gov/cyberframework>
- **CSF 1.1 → 2.0 official crosswalk:** search nist.gov for "CSF 2.0 1.1 to 2.0 crosswalk".
- **CSF Reference Tool** (browse Categories / Subcategories / Implementation Examples in a searchable web UI): <https://csrc.nist.gov/projects/cybersecurity-framework/csf-tool>
- **CIS Controls v8.1 → CSF 2.0 mapping**: published by CIS, search "CIS Controls NIST CSF 2.0 mapping".
- **Quick-start guides** by audience (Small Business, Enterprise, OT, Supply Chain): on the NIST landing page.

## Related repo content

- MITRE ATT&CK coverage map: [`COVERAGE.md`](../COVERAGE.md) — pairs with CSF for the technical / executive crosswalk.
- ISO 27001 crosswalk: [`iso-27001.md`](iso-27001.md).
- SOC 2 crosswalk: [`soc2.md`](soc2.md).
- IRS Publication 1075 crosswalk: [`irs-pub-1075.md`](irs-pub-1075.md).
