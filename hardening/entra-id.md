# Hardening — Microsoft Entra ID: Conditional Access reference baseline

- **Author:** nextlayersec
- **Last updated:** 2026-06-07
- **Maturity:** published — baseline written, drawn from Microsoft's Conditional Access Framework + field experience; refine per tenant
- **Scope:** This guide is the **Conditional Access policy baseline** for an Entra ID tenant — the 10 policies that, in practice, eliminate ~80–90% of identity-side attack patterns we see in the field (password spray, AiTM cookie replay, BEC follow-on, basic-auth abuse, risky sign-in from new countries). It does **not** cover Privileged Identity Management (PIM), Identity Protection licensing, named-locations build-out, or the Tenant Restrictions v2 outbound-policy story — those each get their own guide.
- **Prerequisites:**
  - Tenant on **Microsoft 365 Business Premium**, **E3 + Entra ID P1**, or **E5**. Risk-based policies (PR-AA-04) need **Entra ID P2** (included in E5 or Business Premium with the add-on).
  - One human Global Admin doing the rollout, with a **break-glass account** already created and excluded from every policy (see "Reversal plan" below).
  - All users have at least one MFA method registered (phone is OK to start; phishing-resistant comes in Policy 4).
  - **Audit-mode all policies for 7 days** before enforcing. Conditional Access has a "Report-only" toggle for exactly this.

## Why this matters

Identity is where the breach happens. **Every major SOC-side incident in this repo's threat-intel content starts with an identity compromise** — Scattered Spider's help-desk-driven MFA reset (T1556.006), AiTM session cookie replay (T1539 / T1606.002), password spray (T1110.003). Conditional Access is the single highest-leverage control in M365 / Entra. The baseline below blocks or significantly degrades all three of those primary attack patterns at the identity layer — before they reach mailbox, file, or admin.

## The baseline

The 10 policies are presented in **rollout order** (see next section for the dependency graph). Each policy uses the name you'd actually create in the portal, prefixed with a number for ordering.

### 1. `CA001 — Block legacy authentication`

- **Purpose:** Disable IMAP / POP / SMTP basic auth and other legacy authentication protocols that can't enforce MFA.
- **Scope:** All users, all cloud apps.
- **Conditions:** Client apps → **Exchange ActiveSync clients**, **Other clients**.
- **Control:** Block access.
- **Recommended:** Enforce immediately after a 7-day report-only check confirms no legitimate basic-auth traffic.
- **Break-glass:** Excluded.
- **Why:** Legacy auth has no MFA support — every password spray landing on basic auth bypasses everything else.

### 2. `CA002 — Require MFA for all users`

- **Purpose:** Baseline MFA on every interactive sign-in.
- **Scope:** All users (except break-glass). All cloud apps.
- **Conditions:** none.
- **Control:** Grant → **Require multi-factor authentication**.
- **Recommended:** Enforce after the org has been pushed through user-driven MFA registration (Authentication Methods → registration campaign). Don't enforce while users still need to register; you'll generate help-desk pain.
- **Break-glass:** Excluded.
- **Why:** Baseline. Don't skip even if you think "we already have MFA enforced" — Security Defaults is not equivalent and they can't co-exist with CA.

### 3. `CA003 — Require MFA for admins`

- **Purpose:** Redundant safety net for privileged-role holders, in case CA002 is ever rolled back accidentally.
- **Scope:** Directory roles → Global Admin, Privileged Role Admin, Conditional Access Admin, Security Admin, Helpdesk Admin, Application Admin, Cloud Application Admin, Exchange Admin, SharePoint Admin, User Admin, Authentication Admin, Privileged Authentication Admin (12 roles).
- **Control:** Grant → **Require multi-factor authentication**.
- **Recommended:** Defense in depth. Even with CA002 enforced, lose this defense if someone disables CA002.
- **Break-glass:** Excluded.

### 4. `CA004 — Require phishing-resistant MFA for admins`

- **Purpose:** **The single highest-leverage policy in this baseline.** Blocks AiTM cookie replay against admin accounts. FIDO2 / Windows Hello for Business / certificate-based authentication bind the credential to the legitimate IdP origin via WebAuthn — the AiTM proxy domain fails origin validation and the authenticator refuses to release the assertion.
- **Scope:** Same 12 privileged roles as CA003.
- **Control:** Grant → **Require authentication strength** → **Phishing-resistant MFA**.
- **Recommended:** Roll out FIDO2 security keys to admins **before** enforcing. Then enforce.
- **Break-glass:** Excluded (but the break-glass account itself should be a phishing-resistant FIDO2 key kept in a safe).
- **Why:** Without this, your administrative account is one AiTM phish away from full tenant compromise — even with MFA enforced. See [`threat-intelligence/ttps/aitm-phishing-kits.md`](../threat-intelligence/ttps/aitm-phishing-kits.md).

### 5. `CA005 — Block sign-ins from non-allowed countries`

- **Purpose:** Block sign-ins from regions the org doesn't operate in.
- **Scope:** All users.
- **Conditions:** Locations → exclude the **Allowed Countries** named location (create this first under Settings → Named locations).
- **Control:** Block access.
- **Recommended:** Start with "all countries except where you have employees / contractors / travelers" allowlist. Tune based on legitimate travel hits in audit log.
- **Break-glass:** Excluded.
- **Why:** Roughly 60–80% of credential-stuffing attempts in field telemetry come from countries the target org doesn't operate in. Cheap, high-impact filter.

### 6. `CA006 — Require compliant device for sensitive apps`

- **Purpose:** Bind access to managed, compliant devices for the apps that hold the crown jewels.
- **Scope:** All users.
- **Conditions:** Cloud apps → include **Office 365**, **Microsoft Graph**, **Azure management**, and any high-sensitivity app in your tenant. Optionally start narrower (Azure management only) and expand.
- **Control:** Grant → **Require device to be marked as compliant** (Intune) OR **Require Hybrid Azure AD joined device**.
- **Recommended:** Has Intune dependency — only roll this out after device compliance policies exist. Defer until Intune hardening guide is implemented.
- **Break-glass:** Excluded.
- **Why:** Compromised credentials from an unmanaged personal device can't reach M365 → reduces blast radius of any successful credential phish.

### 7. `CA007 — Block sign-ins at high risk`

- **Purpose:** Block when Identity Protection flags the sign-in as `High` risk.
- **Scope:** All users (except break-glass).
- **Conditions:** Sign-in risk → **High**.
- **Control:** Block access.
- **Recommended:** Requires Entra ID P2. If on P1, use Microsoft Secure Score's risky sign-in alerts instead and rely on CA002 + CA004 for the bulk of the protection.
- **Break-glass:** Excluded.

### 8. `CA008 — Require MFA at medium risk (re-prompt)`

- **Purpose:** Force re-authentication when Identity Protection flags `Medium` risk.
- **Scope:** All users.
- **Conditions:** Sign-in risk → **Medium**.
- **Control:** Grant → **Require multi-factor authentication**.
- **Recommended:** Pair with `CA007`. Note: with `CA002` already enforcing MFA on all sign-ins, this primarily forces MFA re-prompt vs. SSO token reuse — which is the point.
- **Break-glass:** Excluded.

### 9. `CA009 — Sign-in frequency for admins`

- **Purpose:** Cap the lifetime of admin session tokens so a stolen cookie has a short useful window.
- **Scope:** Directory roles (same 12 as CA003).
- **Control:** Session → **Sign-in frequency** → **4 hours**.
- **Recommended:** Pair with **Continuous Access Evaluation (CAE)** at the tenant level for near-real-time token revocation.
- **Break-glass:** Excluded.

### 10. `CA010 — Block guests from sensitive apps`

- **Purpose:** Stop accidental external-user access to internal-only apps. The default tenant configuration is far more permissive than people realize.
- **Scope:** Users → include **All Guest and external users**.
- **Conditions:** Cloud apps → include the apps in your tenant that should never be accessible to guests (HR app, finance app, IT admin apps).
- **Control:** Block access.
- **Recommended:** Audit current guest reach via Access Reviews before flipping this — you'll often find legitimate cross-tenant collaboration that needs explicit allow.
- **Break-glass:** Excluded.

## Rollout order

```text
Pre-flight:
  • Break-glass account exists, FIDO2 key in safe, excluded from every policy
  • Named location "Allowed Countries" created
  • User MFA registration campaign complete (>= 95% registered)
  • Admins have FIDO2 keys issued

Stage 1 — Foundations (week 1):
  1. CA001 Block legacy auth                 ────┐
                                                 ├─ Report-only 7 days
  2. CA002 Require MFA all users             ────┤
                                                 │
  3. CA003 Require MFA admins                ────┘  (redundant safety net)

Stage 2 — Identity hardening (week 2):
  4. CA004 Phishing-resistant MFA admins     ────┐
                                                 ├─ Enforce after Stage 1 + FIDO2 rollout
  5. CA005 Block non-allowed countries       ────┘

Stage 3 — Device + risk (week 3):
  6. CA006 Require compliant device          ── (defer if Intune not yet baselined)
  7. CA007 Block high-risk sign-ins          ────┐
                                                 ├─ Entra ID P2 dependency
  8. CA008 MFA at medium risk                ────┘

Stage 4 — Session + access governance (week 4):
  9. CA009 Sign-in frequency admins
 10. CA010 Block guests sensitive apps
```

## Validation

For each policy, three layers of validation:

1. **Conditional Access What-If tool** (Entra portal → Conditional Access → What If). Simulate the sign-in you're trying to block. The tool tells you which CA policies will apply and what they'll do.
2. **Sign-in audit log filter** (`SigninLogs` in Sentinel / Log Analytics, or the portal). For each enforced policy, filter on `ConditionalAccessPolicies` containing the policy name; confirm you're seeing expected `result: success` blocks / grants.
3. **Detection-side signal:** After rollout, the [`T1110.003 Entra ID password spray`](../detections/kql/T1110.003_entra-password-spray.md) detection should show **a reduction in successful sign-ins** following spray events (the sprays still happen and still get logged at `ResultType != 0`, but no longer convert to logged-in sessions). After CA004, the [`T1078.004 risky sign-in + mailbox rule`](../detections/kql/T1078.004_risky-signin-mailbox-rule.md) detection should drop near-zero for **admin** accounts.

## Common pitfalls

1. **Forgetting to exclude the break-glass account from every policy.** If CA001 + CA002 are enforced and your break-glass account is included, **you have locked yourself out of your tenant**. Make break-glass exclusion the first thing you set when creating each policy.
2. **Enforcing CA006 (compliant device) without Intune in place.** Users on personal devices will be blocked from M365 the moment this enforces. Stage 3 explicitly defers this until Intune is baselined.
3. **Forgetting service principals.** CA policies target users; sign-ins from app registrations / service principals use Workload Identity Conditional Access (a separate license, Entra ID Workload Identities Premium). Don't break Power Automate / Logic App auth at 2 AM Sunday.
4. **Allowing legacy auth "just for that one printer / scan-to-mail."** It will be the entry point for the spray that compromises the org. Solve it with an Exchange Online connector + IP-restricted SMTP submit endpoint, not by leaving basic auth on.
5. **Setting "All cloud apps" on a restrictive policy.** Always test against "Office 365" first; "All cloud apps" includes admin endpoints that you'll need to access *to fix the policy* if it goes wrong.
6. **Enabling the policy outside report-only mode immediately.** Run report-only ≥ 7 days. Check the sign-in log filter `ConditionalAccessStatus = notApplied`-but-`appliedConditionalAccessPolicies`-shows-the-policy. You're looking for *legitimate* sign-ins that *would have been blocked* — these are the things to whitelist or rethink before enforcement.
7. **Forgetting Continuous Access Evaluation.** CA policies are evaluated at sign-in. CAE re-evaluates within ~5 minutes of a critical event (password reset, account disable, risk change). Without CAE, a stolen token can stay valid for an hour even after you've revoked sessions.
8. **Skipping the user comms.** Especially for CA004 (phishing-resistant MFA on admins) and CA005 (country block) — your admins / travelers will lock themselves out the first morning. A 5-minute email saves a 50-minute help-desk ticket.

## Reversal plan

**The break-glass account is the entire reversal plan.** A break-glass account is:

- A cloud-only Global Admin
- Has its password and FIDO2 key in a physical safe accessible to ≥ 2 leaders
- **Excluded from every Conditional Access policy** — verified after each policy edit
- Has its sign-ins fed into a Sentinel alert (`SigninLogs | where UserPrincipalName == "breakglass@..."` → high-severity alert)

If a CA policy locks the tenant out:

1. Sign in with the break-glass account from a managed device.
2. Set the offending policy back to **Report-only** or **Off**.
3. Verify the locked-out account can sign in again.
4. Rotate the break-glass password (any break-glass usage triggers a rotate event by policy).
5. Post-mortem: what changed in the policy, what test was missed, what would have caught it in report-only.

If you don't have a working break-glass account, **stop and create one before touching any policy in this baseline**. The break-glass account is non-negotiable for any CA work.

## Framework mapping

- **MITRE ATT&CK mitigations:**
  - **M1032** — Multi-factor Authentication (CA002, CA003, CA004, CA008)
  - **M1018** — User Account Management (CA003, CA004, CA009)
  - **M1036** — Account Use Policies (CA001, CA005, CA009, CA010)
  - **M1028** — Operating System Configuration (CA006, via Intune compliance)
  - **M1017** — User Training (referenced in pitfalls re. user comms)
- **MITRE ATT&CK techniques significantly degraded:**
  - T1078.004 Cloud Accounts (post-AiTM compromise) → CA004 (phishing-resistant), CA007/CA008 (risk-based)
  - T1110.003 Password Spraying → CA002 (baseline MFA)
  - T1556.006 MFA bypass → CA004
  - T1539 Steal Web Session Cookie → CA009 (sign-in frequency) + CAE
  - T1199 Trusted Relationship → CA010 (guest restrictions)
  - T1078.001 Default Accounts (basic auth) → CA001
- **NIST CSF 2.0:**
  - **PR.AA-01** Identities and credentials managed (all policies)
  - **PR.AA-04** Identity assertions are protected, conveyed, and verified (CA004)
  - **PR.AA-05** Access permissions / entitlements managed (CA006, CA010)
  - **DE.AE-02** Adverse-event signals analyzed (CA007, CA008 via Identity Protection)
- **ISO 27001:2022:**
  - **A.5.17** Authentication information (all)
  - **A.8.5** Secure authentication (CA002, CA003, CA004, CA008)
  - **A.8.2** Privileged access rights (CA003, CA004, CA009)
- **CIS Controls v8.1:**
  - **5** Account Management
  - **6** Access Control Management
  - **13.6** Use of MFA for administrative access (CA003, CA004)
  - **16.3** Filter web-based connections by risk score (CA005, CA007)

## Related repo content

- Detections: [`T1110.003 Entra ID password spray`](../detections/kql/T1110.003_entra-password-spray.md), [`T1078.004 risky sign-in + mailbox rule`](../detections/kql/T1078.004_risky-signin-mailbox-rule.md), [`T1566.001 delivered phish with harvester link`](../detections/kql/T1566.001_attachment-link-credential-harvester.md)
- Threat-intel: [`AiTM phishing kits`](../threat-intelligence/ttps/aitm-phishing-kits.md), [`Scattered Spider actor profile`](../threat-intelligence/actors/scattered-spider.md)
- Playbook: [`Phishing email triage`](../blue-team-playbooks/phishing-email-triage.md)
- Framework: [`NIST CSF 2.0`](../frameworks/nist-csf.md)

## References

- **Microsoft Conditional Access Framework** (2024) — Microsoft's reference CA policy bundle. Search Microsoft Learn for "Conditional Access policy templates".
- **Microsoft Authentication Strengths** — phishing-resistant MFA authentication strength reference. Microsoft Learn → "Authentication strengths".
- **CISA Joint Guidance — Phishing-Resistant MFA** (October 2022) — explicit recommendation pattern.
- **CISA AA23-320A — Scattered Spider** (November 2023) — primary source for the threat patterns this baseline counters.
- **Microsoft Security Baselines** for M365 — separately published; this guide is a tighter, ordered subset focused on Conditional Access.
