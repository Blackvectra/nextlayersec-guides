# Hardening guides

Practical, opinionated baselines for **preventing** the things the rest of this repo helps you **detect** and **respond to**. Each guide:

- Targets one platform / service (Entra ID, Microsoft 365, Windows endpoint, etc.)
- Is **deployable** — the steps lead to a measurable end-state in a real tenant
- Has a **rollout order** with dependencies called out (you can't enforce phishing-resistant MFA before you've registered methods)
- Includes a **validation method** so you can prove the control is doing what it says
- Cross-walks to MITRE ATT&CK mitigations, NIST CSF 2.0 Subcategories, ISO 27001:2022 Annex A, and CIS Controls v8.1
- Is biased toward the **Windows-MSP environment** this repo serves — Microsoft 365 Business Premium / E3 / E5, Defender for Endpoint, Entra ID, Intune

## Naming convention

`hardening/<platform-or-service>.md`. Lowercase, hyphenated.

## File pairing

Hardening guides don't need a paired query file the way detections do, but they often reference:

- Detections in `detections/kql/T*.kql` that fire **before** the hardening is in place (proving the gap)
- Detections that fire **after** the hardening is in place (proving residual risk)
- Playbooks in `blue-team-playbooks/` that the hardening reduces the likelihood of needing

Cross-link generously.

## Index

| Platform / service | File | Status |
|---|---|---|
| **🔒 NextLayerSec non-negotiable baseline** | [`nextlayersec-baseline.md`](nextlayersec-baseline.md) | **published — enforced on every client tenant** |
| Microsoft Entra ID — Conditional Access reference | [`entra-id.md`](entra-id.md) | published (initial) |
| Windows endpoint — ASR / WDAC / Credential Guard / BitLocker | [`windows-endpoint.md`](windows-endpoint.md) | published (initial) |
| Microsoft 365 — anti-phishing + impersonation | _todo_ | planned |
| Defender for Endpoint baseline | _todo_ | planned |
| Intune compliance + configuration | _todo_ | planned |
| Network — tenant restrictions v2 + DMARC | _todo_ | planned |
| Azure — Defender for Cloud baselines | _todo_ | planned |
| Sentinel essential analytic rules pack | _todo_ | planned |

## Verdict discipline

Each guide ends with a **`Verdict` / `Maturity` line** that the author updates when they validate the baseline in a real tenant:

- `Maturity: published — baseline written` (paper-only, not yet tested)
- `Maturity: validated — implemented in 1+ tenant` (proved it works)
- `Maturity: hardened — refined after multiple rollouts` (real-world tested, refinements baked in)

Stay honest about this. A paper-only hardening guide that's never been tried is worth roughly half a battle-tested one — and the reader needs to know the difference.

## Use [`_template.md`](_template.md) when starting a new guide.
