# Compensating Controls — Reference

- **Author:** nextlayersec
- **Last updated:** 2026-06-07
- **Maturity:** validated — this is how NextLayerSec evaluates compensating controls for the [non-negotiable baseline](nextlayersec-baseline.md) exception process
- **Scope:** What a *real* compensating control is, what disqualifies one, and a worked list of acceptable substitutes for the most common baseline gaps.

## Why this document exists

The baseline says "phishing-resistant MFA on admins." A client says "we can't roll FIDO2 keys for 90 days." What's an acceptable bridge for those 90 days? That's a compensating control question.

People wave the term around without rigor. This document defines the rigor.

## What is a compensating control?

A compensating control is **an alternative measure that achieves equivalent risk reduction** when the primary control cannot be implemented. It is not:

- ❌ A weaker version of the same control
- ❌ Hope, training, or "people will be careful"
- ❌ Detection without prevention (detection is necessary but does not compensate for missing prevention by itself)
- ❌ A promise to revisit later
- ❌ "We have a policy that says…"

A real compensating control has **three required properties**:

1. **Substitutes the risk reduction**, not just the activity. (Email gateway URL blocking does not substitute for endpoint URL blocking — different attack vectors.)
2. **Is time-boxed when temporary**, or has its own quarterly reaffirmation when permanent.
3. **Has its own validation method.** If you can't tell whether the compensating control is working, you don't have a compensating control — you have a wish.

## The compensating-control test

For any proposed substitute, all five answers must be "yes":

| Test | Answer must be |
|---|---|
| Does it stop / detect the **same** attack pattern the original control addresses? | Yes — specific pattern, not vague |
| If the original control would have caught attack X, does this control also catch attack X? | Yes — write down attack X |
| Is its validation method as concrete as the original control's? (a query, a portal location, a test) | Yes — point at the validation |
| Is the residual risk **explicitly accepted** by a named business owner? | Yes — name and date |
| Is there a date when this control is re-evaluated? | Yes — quarterly or sooner |

If any answer is "no" or "kind of," **this is not a compensating control**. It is risk acceptance with extra words.

## Acceptable compensating controls — worked list

The table below maps the most common baseline gaps to acceptable temporary or permanent substitutes. **None of these are as good as the original control.** They buy time or accept degraded confidence.

### Identity — Entra ID

| Baseline gap | Acceptable compensating control | Type | Time limit |
|---|---|---|---|
| **1.3 Phishing-resistant MFA on admins not yet rolled out** | Hardware OATH-TOTP token (YubiKey OATH or similar) + Conditional Access requiring `MFA` + IP-locked sign-in (admin sign-in only from named-location office/VPN egress) | **A — temporary** | **90 days** while FIDO2 keys roll out |
| **1.5 No standing Global Admins — but PIM not licensed** | At least 2 named Global Admin accounts, daily review of GA membership via automation (script that emails on drift), quarterly access review with signed attestation | **B — permanent** (EOL-licensing tier) **OR A — temporary** (waiting for P2 add-on) | **Quarterly reaffirmation** (B) or **90 days** to license + enable PIM (A) |
| **1.4 Break-glass account exists but is NOT FIDO2** | TOTP-based MFA on break-glass account, password length ≥ 32 chars, password in physical safe with sealed envelope, FIDO2 ordered with delivery date documented | **A — temporary** | **30 days** to physical key delivery |
| **CA001 Block legacy auth — but one LOB app needs IMAP** | Dedicated Entra-restricted account for the LOB app (no other roles), IP-restricted application access policy, Microsoft 365 retention + audit on that mailbox, plan to retire LOB app integration documented with date | **B — permanent** | **Reaffirm quarterly** + retirement plan |

### Email — Defender for Office 365

| Baseline gap | Acceptable compensating control | Type | Time limit |
|---|---|---|---|
| **2.1 Anti-phish impersonation not configured** | Tenant Allow/Block List entries for known-impersonated domains (your major customers / partners), mail-flow rule that adds an external-sender banner to emails matching impersonation patterns, monthly review of `EmailEvents` for impersonation hits | **A — temporary** | **30 days** to fully configure anti-phish policy |
| **2.4 DMARC at `p=none`** | SPF strict (`-all`), DKIM signing all outbound mail, **published rua reporting** with daily review of DMARC report aggregates, plan to walk through `none → quarantine → reject` documented with dates | **A — temporary** | **90 days** to reach `p=quarantine` |
| **2.2 Safe Attachments Block mode not yet rolled out** | Safe Attachments in **Dynamic Delivery** mode (slightly slower delivery, equivalent block), exec / finance recipients in stricter sub-policy | **B — permanent** | **OK as compensating control long-term** if Dynamic Delivery is in place |

### Endpoint — Defender for Endpoint + Intune

| Baseline gap | Acceptable compensating control | Type | Time limit |
|---|---|---|---|
| **3.4 ASR rules in Audit, not Block** | Audit-mode telemetry actively reviewed weekly with action on findings; documented plan to progress to Block per rule; the [`T1059.001`](../detections/kql/T1059.001_powershell-encoded-command.md) detection deployed and tuned | **A — temporary** | **30 days** to flip each rule from Audit to Block (one-at-a-time progression OK) |
| **3.5 BitLocker not enabled on legacy laptops** | Legacy laptops are tagged in Intune, blocked from accessing M365 via Conditional Access requiring compliant device; replacement schedule documented | **A — temporary** | **By end of next hardware refresh cycle** (typically ≤ 18 months) |
| **3.6 LSA-PPL not deployed** | Credential Guard enabled (provides defense-in-depth; not equivalent — LSA-PPL is still required), plus the [`T1003.001 LSASS access`](../detections/kql/T1003.001_lsass-access-suspicious.md) detection deployed and alerting on every Defender XDR incident | **A — temporary** | **30 days** to push LSA-PPL via Intune |

### Backup

| Baseline gap | Acceptable compensating control | Type | Time limit |
|---|---|---|---|
| **4.1 No immutable backup product yet** | M365 Retention Policies enabled for at least 90 days on mailbox + SharePoint + OneDrive, plus periodic manual export of critical mailboxes to encrypted offline storage | **A — temporary only** | **30 days** to procure backup product. **Not acceptable permanently** — M365 retention is not backup. |
| **4.3 Restore not tested in 90 days** | Test scheduled within the next 7 days; documented ticket | **A — temporary** | **7 days** |

### Logging

| Baseline gap | Acceptable compensating control | Type | Time limit |
|---|---|---|---|
| **5.3 No Sentinel / SIEM ingestion** | Defender XDR advanced hunting used for ad-hoc queries (30-day retention only), exported critical incident artifacts manually to long-term storage | **A — temporary** | **90 days** to stand up Sentinel or third-party SIEM |

## Compensating controls that are NOT acceptable

These come up. They look reasonable. They don't survive an audit.

| What people propose | Why it's not a compensating control |
|---|---|
| "User training" as a substitute for MFA | Training does not prevent credential theft — it reduces it. Training is a baseline expectation, not a compensating control. |
| "We monitor sign-ins" as a substitute for blocking risky sign-ins | Detection without prevention means you respond *after* the attacker is in. Not equivalent. |
| Allowing legacy auth "only for the printer" | The attacker doesn't care that the legitimate use case is a printer. The endpoint is open. |
| Single break-glass account managed by IT-only | If IT is compromised, the break-glass is too. Split control across at least two people. |
| "We have a policy" without enforcement | A policy is a description of intent. A control is an enforcement mechanism. They are not the same. |
| "We're moving away from that LOB app eventually" | Not a control. Document the retirement plan and treat current state as Type B exception with quarterly reaffirmation until actually retired. |

## How this gets used

Within the **non-negotiable baseline's exception process**:

- **Type A — implementation delay:** the client commits to remediation within ≤ 90 days. The compensating control is what's in place during those 90 days.
  - **Required:** written acceptance from a named business owner + documented compensating control from the acceptable list above (or equivalent that passes the compensating-control test).
  - **Re-evaluated:** at remediation date.
- **Type B — permanent non-conformance:** the client cannot implement the primary control.
  - **Required:** written acceptance from a named business owner (not IT — the **business owner**, accountable for the loss if the control fails) + compensating control from the acceptable list + quarterly reaffirmation.
  - **Re-evaluated:** every quarter, indefinitely.

## Documentation requirements

For every compensating control in use in a client tenant, NextLayerSec maintains:

1. **The baseline item it substitutes for** (link to specific row in `nextlayersec-baseline.md`)
2. **The specific compensating control in place** (link to specific row in this document, or custom write-up)
3. **The validation method** (specific query / portal location / test)
4. **The named business owner** who accepted the residual risk
5. **The implementation date** of the compensating control
6. **The re-evaluation date** (next quarterly review for Type B, remediation date for Type A)
7. **The remediation plan** (specifically what would have to be true to remove the compensating control)

When something is missing from this list, it's not a compensating control. It's drift.

## Related repo content

- **The baseline:** [`hardening/nextlayersec-baseline.md`](nextlayersec-baseline.md)
- **Reference how-to:** [`hardening/entra-id.md`](entra-id.md), [`hardening/windows-endpoint.md`](windows-endpoint.md)
- **The framework hook:** every compensating control should be filed against NIST CSF 2.0 Subcategories — see [`frameworks/nist-csf.md`](../frameworks/nist-csf.md). For audit / insurance evidence, the compensating control register is the artifact.

## Maintenance

- New compensating-control patterns added when they emerge from real client engagements and survive an audit
- Patterns removed when Microsoft / vendor changes make them invalid (e.g., a "compensating control" that depends on a feature being removed)
- Reviewed annually alongside the baseline review
