# NextLayerSec — Non-Negotiable Security Baseline

- **Author:** nextlayersec
- **Last updated:** 2026-06-07
- **Maturity:** validated — this is the standard NextLayerSec applies to every client tenant in production
- **Status:** **NON-NEGOTIABLE.** Items in this document are the **floor**, not the goal. A client tenant either meets this baseline or NextLayerSec is not responsible for the resulting incident.

## What this document is

The **minimum security configuration NextLayerSec enforces on every Microsoft 365 / Windows environment we manage**. It is **opinionated, prescriptive, and non-negotiable**. Each item answers:

- **What** must be true
- **How** we verify it (a specific query, portal location, or PowerShell command — not "ensure that…")
- **Why** — the specific attack pattern it shuts down
- **What happens if it's not** — either we get it implemented, or the engagement does not start / continue

Reference guides like [`entra-id.md`](entra-id.md) and [`windows-endpoint.md`](windows-endpoint.md) describe the *how* in depth. This document is the *what*. They are not interchangeable.

## When this applies

| Trigger | What we do |
|---|---|
| **New client onboarding** | All items audited as part of the kickoff. **Gaps must be remediated within the first 30 days or the engagement does not proceed past pilot.** |
| **Quarterly tenant review** | All items re-audited every 90 days. Drift = ticket + 14-day remediation window. |
| **Post-incident review** | All items re-audited regardless of incident cause. |
| **Cyber-insurance renewal** | This document is the evidence pack. |

## The baseline

### 1. Identity — Entra ID

| # | Requirement | Verify | Why |
|---|---|---|---|
| 1.1 | **Conditional Access policy `CA001 Block legacy auth` is enforced (not report-only).** | Entra → Conditional Access → policy state = `On`. Confirm `SigninLogs \| where ClientAppUsed in ('Other clients', 'Exchange ActiveSync') and ResultType == 0 \| count` returns `0` over last 7 days. | Closes the universal credential-spray entry point. Non-negotiable. |
| 1.2 | **MFA enforced on every interactive sign-in.** Security Defaults is **not** acceptable (it has gaps and can't co-exist with custom CA). | `SigninLogs \| where ResultType == 0 \| where AuthenticationDetails !contains "MFA" \| count` returns `0` over last 30 days for non-break-glass accounts. | Without this every other identity control degrades. |
| 1.3 | **Phishing-resistant MFA enforced on every privileged role** (Global Admin, Privileged Role Admin, Conditional Access Admin, Security Admin, Helpdesk Admin, Application Admin, Cloud Application Admin, Exchange Admin, SharePoint Admin, User Admin, Authentication Admin, Privileged Authentication Admin — the 12 roles in `CA004` of the Entra reference). | CA policy targeting these 12 roles with authentication strength = phishing-resistant MFA is `On`. Test sign-in attempt from a password+TOTP combination fails. | Single highest-leverage policy. AiTM cookie replay is the #1 way admins lose tenants. See [`threat-intelligence/ttps/aitm-phishing-kits.md`](../threat-intelligence/ttps/aitm-phishing-kits.md). |
| 1.4 | **Break-glass account exists, FIDO2 key in physical safe, excluded from every CA policy.** | Account documented; key location documented; CA policy exclusions verified per policy; `SigninLogs \| where UserPrincipalName == "<breakglass>@…"` feeds an analytic rule that pages on any sign-in. | If anything in this baseline locks the tenant out, the break-glass account is the only way back in. |
| 1.5 | **No standing Global Admins.** Global Admin role held by ≥ 2 named individuals AND access is just-in-time (PIM where licensed, eligible-only) — not permanent. Break-glass account is the only standing GA. | Entra → Roles → Global Admin members. PIM eligible vs. active assignments. | A compromised admin with permanent GA loses the tenant in 90 seconds. JIT cuts that risk dramatically. |
| 1.6 | **Country block enforced (`CA005`).** Allowed-countries named location matches actual operating geography. | CA policy `On`, named location membership matches client business footprint. | Roughly 60–80% of credential stuffing originates outside the operating geography. Cheap, high-impact filter. |

### 2. Email — Defender for Office 365

| # | Requirement | Verify | Why |
|---|---|---|---|
| 2.1 | **Anti-phishing policy with impersonation protection for the client's executive team AND impersonated-domain protection for the client's primary domain.** | Defender → Email & collaboration → Policies & rules → Anti-phishing → policy exists; impersonated users count ≥ exec team size; impersonated domains include all client domains. | A real internal incident on file would have been prevented if this policy had been configured ahead of the impersonation campaign — anti-phishing impersonation is the single highest-impact email policy. |
| 2.2 | **Safe Attachments policy with Dynamic Delivery + Safe Documents.** | Policy exists, `EnableSafeDocs = true`, action = `DynamicDelivery` or `Block`. | Password-protected payload PDFs and attachment-borne droppers. |
| 2.3 | **Safe Links policy with click-time URL rewriting + tracked URL clicks.** | Policy exists, `IsEnabled = true`, `DeliverMessageAfterScan = true`, `TrackClicks = true`. | Feeds the [`T1566.001 detection`](../detections/kql/T1566.001_attachment-link-credential-harvester.md) on clicker side. |
| 2.4 | **DMARC published at `p=quarantine` minimum (`p=reject` preferred) on every client-owned sending domain.** | `dig +short TXT _dmarc.<domain>` returns `v=DMARC1; p=quarantine; rua=…` or `p=reject`. | Without DMARC enforcement, your client's brand can be spoofed at zero attacker cost. |
| 2.5 | **Tenant Allow/Block List exists and is actively maintained.** | Defender → Email & collaboration → Tenant Allow/Block Lists has at least one entry; entries documented per case. | Operational hygiene; demonstrates the SOC is acting on IOCs. |

### 3. Endpoint — Defender for Endpoint + Intune

| # | Requirement | Verify | Why |
|---|---|---|---|
| 3.1 | **Every Windows endpoint enrolled in Intune AND onboarded to Defender for Endpoint.** | Intune device count == Defender device count (within 24h sync window). `DeviceInfo \| where OSPlatform startswith "Windows"` row count matches Intune enrolled-Windows count. | Anything not onboarded is a blind spot; the detections in `detections/kql/` only work on onboarded devices. |
| 3.2 | **Tamper Protection enabled tenant-wide.** | Defender → Settings → Endpoints → Advanced features → Tamper Protection = `On`. | Without this, the first thing post-compromise an attacker does is disable Defender. |
| 3.3 | **EDR in block mode enabled.** | Defender → Settings → Endpoints → Advanced features → EDR in block mode = `On`. | Behavioral detections that ALERT-only without this; block-mode actually stops the payload. |
| 3.4 | **The 8 high-impact ASR rules in Block mode** (see [`windows-endpoint.md`](windows-endpoint.md) item 3). | `DeviceEvents \| where ActionType == "AsrBlockedEvent" \| summarize count() by RuleName` returns non-zero for the 8 rules over last 30 days. | LOLBin-via-Office is the most common ransomware-affiliate entry pattern. ASR closes it. |
| 3.5 | **BitLocker enabled on every Windows endpoint; recovery key escrowed to Entra.** | Intune → Devices → Encryption report → 100% encrypted, 100% recovery key in Entra. | Lost / stolen device cannot become a data breach. |
| 3.6 | **LSA Protection (PPL) enabled.** | Intune Settings Catalog → `Configure LSASS to run as a protected process` = enabled, deployed to all devices. | Counters Mimikatz / ProcDump credential dumping. Pairs with the [`T1003.001 LSASS`](../detections/kql/T1003.001_lsass-access-suspicious.md) detection. |

### 4. Backup + recovery

| # | Requirement | Verify | Why |
|---|---|---|---|
| 4.1 | **Immutable backups of M365 mailbox + OneDrive + SharePoint** to a backup product with attacker-tamper-resistant retention. | Backup product running (Veeam M365 / Datto / AvePoint / etc.); last successful backup ≤ 24 hours old; retention policy ≥ 90 days; immutability = `On`. | M365 retention is not backup. Ransomware affiliates increasingly target M365 data directly. |
| 4.2 | **Backup admin credentials are separate** from M365 admin credentials. | Backup admin is a non-Entra account (or a separate Entra account with no M365 admin roles). | Stops "compromise M365 admin → delete backups in one motion." |
| 4.3 | **Restore tested in last 90 days.** | Ticket documenting a successful restore (test or production) within 90 days. | Untested backups are not backups. |

### 5. Logging + monitoring

| # | Requirement | Verify | Why |
|---|---|---|---|
| 5.1 | **Defender XDR onboarded and feeding** all five workloads where licensed: Endpoint, Office, Identity, Cloud Apps. | Defender → Settings → Microsoft Defender XDR → all data connectors show `Healthy`. | Without this, the detections in this repo have nothing to fire against. |
| 5.2 | **Unified Audit Log enabled** in Exchange Online. | `Get-AdminAuditLogConfig` returns `UnifiedAuditLogIngestionEnabled = True`. | Mailbox-rule changes, OAuth grants, sign-ins — the [`T1078.004 detection`](../detections/kql/T1078.004_risky-signin-mailbox-rule.md) depends on this. |
| 5.3 | **Sentinel or equivalent SIEM ingesting `SigninLogs`, `OfficeActivity`, `DeviceProcessEvents`, `DeviceFileEvents`, `EmailEvents`, `UrlClickEvents`** with minimum 90-day retention. | Sentinel workspace exists or third-party SIEM ingest confirmed; query returns rows for each table for last 30 days. | The hunt queries in case files (see incidents repo) assume these are queryable. |

### 6. Incident response

| # | Requirement | Verify | Why |
|---|---|---|---|
| 6.1 | **NextLayerSec contact documented as the security incident POC inside the client tenant**, with 24/7 reachability info. | Tenant settings → Organizational information → security contact email = NextLayerSec ops mailbox. Documented in the client runbook. | When Microsoft auto-detects a critical incident, we get notified directly. |
| 6.2 | **Break-glass-account sign-in fires a Sentinel / Defender XDR analytic rule that pages on-call.** | Rule exists, severity = High, action group includes on-call PagerDuty / phone number. | The break-glass account is supposed to be used once a year. If it's used, *something is on fire*. |
| 6.3 | **Phishing-report user button (PAB) deployed** to every mailbox via Defender for Office 365. | `Get-ReportSubmissionPolicy` returns enabled; PAB visible in Outlook for a test mailbox. | Users report phish — but only if it's a one-click action. Without PAB, you lose the cheapest detection channel you have. |

## Audit procedure

The full baseline audit runs as a single PowerShell script in the client tenant + a manual portal walkthrough. The script lives at `scripts/baseline-audit.ps1` (separate item — bootstrap pending). For now, the audit is performed by walking this document item-by-item and ticking each in the client runbook.

A passing audit is a single PDF artifact: this document with every item ticked, dated, and signed by the auditor. Quarterly re-audits replace the previous PDF.

## Exception process

Two exception types — both **explicit**, **documented**, and **time-boxed**:

### Type A — Implementation delay

Client is committed but needs > 30 days to remediate (e.g., FIDO2 keys ordered, BitLocker requires hardware refresh for unsupported devices).

- Written acceptance of risk by client decision-maker
- Defined remediation date (≤ 90 days from baseline gap identified)
- Compensating control documented (e.g., conditional access requiring MFA + risky-sign-in block until phishing-resistant MFA rolls out)
- Re-audit on remediation date

### Type B — Permanent non-conformance

Client cannot or will not meet the requirement (e.g., legacy line-of-business app requires basic auth).

- Written acceptance of risk by client decision-maker (NOT IT — the business owner)
- Compensating control documented with rationale
- Logged in a tenant-specific exception register
- Reviewed at every quarterly audit; reaffirmation required each quarter

**There is no Type C.** "We don't want to do that" without written exec sign-off is not an exception — it's an engagement-ending disagreement.

## Why this is non-negotiable

NextLayerSec's exposure to a single client incident reaches every other client in the practice via:

1. **Reputation** — "MSP X's client got breached" is the story that loses you the next 5 sales conversations
2. **Insurance** — your cyber liability premium is rated against your highest-risk client
3. **Operational cost** — incident-response work is unbillable past initial scope; a poorly-baselined client is operational debt you can't sell

Each item in this baseline is **already in the threat-intel content of this repo**. The Scattered Spider profile, the AiTM TTP roundup, and internal case files describe what happens when items in this list are missing. They are not theoretical.

## Related repo content

- Reference guide: [`hardening/entra-id.md`](entra-id.md) — how to implement Section 1 in detail
- Reference guide: [`hardening/windows-endpoint.md`](windows-endpoint.md) — how to implement Section 3 in detail
- Threat-intel: [`threat-intelligence/actors/scattered-spider.md`](../threat-intelligence/actors/scattered-spider.md), [`threat-intelligence/ttps/aitm-phishing-kits.md`](../threat-intelligence/ttps/aitm-phishing-kits.md)
- Framework crosswalk: [`frameworks/nist-csf.md`](../frameworks/nist-csf.md) — every item in this baseline maps to a CSF Subcategory (handy for cyber-insurance evidence packs)
- Incident reference: internal post-incident records, indexed against the relevant baseline item — every gap in this list has a concrete case-record of what happens when the control isn't in place

## Maintenance

- Re-evaluated **annually** (every January) against the prior year's incidents, threat-landscape shifts, and Microsoft product changes
- Items added when post-incident review reveals a missing control
- Items relaxed only with a 90-day notice + documented rationale
