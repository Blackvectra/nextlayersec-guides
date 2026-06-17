# Playbook: Cloud Account Compromise (Entra ID / Microsoft 365)

A response playbook for the canonical Microsoft 365 / Entra ID account-compromise pattern: a tenant user (regular, admin, or service principal) gets their credentials or session stolen, the attacker rides the account into Exchange / SharePoint / Teams / Graph for data theft, internal phishing, or persistence. This playbook focuses on **post-compromise containment + persistence eradication regardless of how the credentials were obtained**.

- **Author:** nextlayersec
- **Last updated:** 2026-06-11
- **Scope:** Microsoft 365 / Entra ID tenant (Business Premium / E3 / E5). Hybrid AD if present. The shape transfers to Okta / AWS / GCP but the surfaces differ.

## Trigger

Activate this playbook when any of:

- T1078.004 risky sign-in + mailbox-rule mutation detection fires.
- T1110.003 password-spray detection fires with a `LogonSucceeded` count > 0.
- T1021.001 RDP from unusual source fires with `B_External` (cloud-VM compromise pivots here).
- Defender for Cloud Apps surfaces a `RiskySignIn`, `MassDownload`, `UnusualVolumeOfFileDeletion`, or `ImpossibleTravel` alert.
- Entra ID Identity Protection flags a user as **High risk** (`riskLevel: high`).
- A user self-reports: unexpected MFA prompt, unfamiliar sign-in alert, mailbox-rule they didn't create, OAuth consent they didn't grant, Teams chat from their account that they didn't send.
- Microsoft Threat Intelligence surfaces a compromised credential from breach data matching one of your users.

## Scope of the incident

Determine before responding:

1. **Tier of the affected principal.** Regular user → standard response. Helpdesk admin → escalated. Global Admin / Exchange Admin / Privileged Role Administrator → emergency. Service principal / managed identity → very different containment surface (app registration secrets, not user passwords).
2. **Compromise method.**
   - Password spray / brute force → credentials only, MFA may still be enrolled.
   - AiTM / token theft (Evilginx, Tycoon, Storm-0867 patterns) → **session tokens AND MFA were bypassed** — see `threat-intelligence/ttps/aitm-phishing-kits.md`.
   - OAuth consent phishing → user granted an attacker app `Mail.Read` / `Files.Read.All` / `Sites.Read.All` etc. — attacker has persistent access via the OAuth grant, not via the user's password.
   - Stolen device session → unlocked corporate device left unattended → attacker has the user's whole context.
   - Insider — user gave / sold credentials voluntarily. Treat as HR + legal in addition to IR.
3. **Persistence touched.** Has the attacker added an MFA method? Created an inbox rule? Granted themselves an OAuth app? Created a backup admin account?
4. **Data exfiltrated?** `MailItemsAccessed` audit log, SharePoint download events, Teams chat exports.

## Triage (first 15 minutes)

| # | Action | Tool / surface |
|---|---|---|
| 1 | Confirm not a false positive by pulling the matching `SigninLogs` rows | Entra ID → Sign-ins, Defender XDR advanced hunting |
| 2 | Get the source IP + user-agent + matching client app | `SigninLogs` |
| 3 | Establish blast radius — how many accounts have authentication events from the same IP / user-agent in the last 7 days? | `SigninLogs \| where IPAddress == "<ip>" or UserAgent == "<ua>" \| summarize count() by UserPrincipalName, ResultType` |
| 4 | Identify the highest-tier compromised account in the set | Entra ID → Users → role memberships |
| 5 | Notify affected user(s) out of band — phone, NOT email (the attacker may be reading their email) | — |

## Containment (next 30 minutes)

### Per-account containment

For every confirmed-compromised account:

1. **Revoke all sessions** — Entra ID → Users → [account] → Sessions → "Revoke all sessions" (or `Revoke-AzureADUserAllRefreshToken` in PowerShell). Invalidates every refresh token; forces re-auth on every device.
2. **Force password change** at next sign-in. Reset to a temporary password communicated out-of-band.
3. **Force MFA re-enrollment.** Entra ID → Users → [account] → Authentication methods → "Require re-register MFA". This removes any AiTM-stolen tokens AND any attacker-added auth methods.
4. **Block sign-in** temporarily if the account is high tier — Entra ID → Users → [account] → "Block sign-in" → Yes. Better to call a Global Admin offline than to leave a possibly-compromised one active.
5. **Audit the account's authentication methods** — Entra ID → Users → [account] → Authentication methods. **Any method the user did not add personally is attacker persistence.** Common attacker-added methods: alternate phone number, FIDO2 key, alternate email, voice call. Remove on sight.
6. **Audit Conditional Access exclusions** — was the account on a CA exclusion list? Why? Remove the exclusion if not justified by current policy.
7. **Audit OAuth app consents** — Entra ID → Users → [account] → Applications. Revoke any app the user did not consent to personally. Particular red flags: any app requesting `Mail.Read*` / `Files.Read.All` / `Sites.Read.All` / `User.Read.All` / `Directory.Read.All` that the user can't explain.

### Tenant-wide containment

1. **Block the source IP at the perimeter** AND in Entra ID Conditional Access (create a Named Location "Compromise YYYY-MM-DD — block" containing the IP).
2. **Block the user-agent** if it's identifiable (curl / python-requests / common AiTM-kit signatures).
3. **Lower the Conditional Access risk threshold** temporarily — escalate "medium" sign-in risk to "block" instead of "MFA challenge" for 24-48 hours.
4. **Run a tenant-wide signature search** — same source IP / user-agent across all `SigninLogs`. Add new hits to the contained-accounts list and loop.
5. **Service principals.** If the compromise is to a Service Principal / Managed Identity rather than a user: rotate the app's client secret (Entra ID → App registrations → [app] → Certificates & secrets), audit the app's permission scope, audit the app's recent sign-ins via `AADServicePrincipalSignInLogs`.

## Eradication (next 1-4 hours)

For each confirmed-compromised account:

1. **Mailbox inbox rules** — `MailboxAuditLog` for `New-InboxRule` and `Set-InboxRule` events from the compromised UPN. Common attacker rules: forward externally, auto-delete replies, move to a hidden folder, move messages from a partner domain to RSS Subscriptions. Disable + delete every rule the user can't account for. Audit via Defender XDR advanced hunting:
   ```kql
   AuditLogs
   | where Identity == "<UPN>"
   | where OperationName in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Add-RecipientPermission", "Add-MailboxPermission")
   ```
2. **Mailbox delegate / forwarding permissions** — Exchange Online → `Get-Mailbox <UPN> | FL ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward`. Remove any unexpected forward.
3. **OAuth consents** the user granted — Entra ID → Users → [account] → Applications → revoke anything they can't explain. Investigate apps matching the AiTM phishing-kit signatures in `threat-intelligence/ttps/aitm-phishing-kits.md`.
4. **Application impersonation / ApplicationImpersonation role** — used by some attackers for tenant-wide mailbox read access. Verify no new Exchange Online RBAC assignments to the compromised account.
5. **Recent SharePoint / OneDrive file shares** — if compromised during business hours, the attacker may have shared files externally. Audit:
   ```kql
   AuditLogs
   | where Identity == "<UPN>"
   | where OperationName in ("SharingSet", "AnonymousLinkCreated", "FileAccessed")
   | where TimeGenerated > <compromise-window-start>
   ```
6. **Microsoft Teams chats from the account** during the compromise window — attackers use Teams for internal phishing pivots.
7. **Hybrid AD if applicable** — for the matching `samAccountName`, audit `eventID 4624 LogonType=10` (RDP) and `LogonType=3` (network) during the compromise window.
8. **Service-credential rotation** — roll any secrets the user could have viewed (password-manager folders they had access to, hardcoded creds in scripts they'd seen, Azure DevOps PATs they owned, Power Platform connection references, Graph app secrets they'd seen).
9. **Customer-facing IOCs** — if the user manages client systems (MSP context), notify the affected client tenants. Roll any API keys for client systems the user managed.

## Recovery (same day)

1. **Restore account access** with new credentials + freshly-enrolled MFA only after eradication.
2. **Sign-in monitoring** for 14 days — pin a dashboard panel:
   ```kql
   SigninLogs | where UserPrincipalName == "<UPN>" | where RiskState != "none"
   ```
3. **MFA step-up Conditional Access policy** for the affected accounts — require MFA + compliant device for 30 days.
4. **Communicate** to the user: what happened, what was done, what they should do (rotate any password they reused elsewhere).

## Lessons learned (week-after review)

Required output for every cloud-account-compromise incident:

1. **Initial vector** — password spray / AiTM token theft / OAuth consent phishing / device theft / insider.
2. **Why MFA didn't stop it** — wasn't enrolled, was bypassed (token theft / SIM-swap), or wasn't required by Conditional Access for this combination.
3. **Why Conditional Access didn't stop it** — gap in named location, exclusion that shouldn't have existed, sign-in risk threshold too lenient.
4. **Time to detection** — earliest event vs SOC first-look.
5. **Time to containment** — sessions revoked, password reset, MFA re-enrolled.
6. **Time to eradication** — inbox rules removed, OAuth consents revoked.
7. **Baseline gap closed** — every incident should update at least one item in `hardening/entra-id.md` / `hardening/nextlayersec-baseline.md` or the matching detection's tuning section.

## Framework mapping

| Framework | Mapping |
|---|---|
| **MITRE ATT&CK** | T1078.004 (Valid Accounts: Cloud Accounts), T1556 (Modify Authentication Process — added MFA methods, inbox rules, app consents), T1098.001 (Account Manipulation: Additional Cloud Credentials), T1114.002 (Email Collection: Remote Email Collection), T1530 (Data from Cloud Storage Object), T1199 (Trusted Relationship — for MSP-tenant pivot). |
| **NIST CSF 2.0** | `DE.CM-01` (network monitoring), `RS.MI-01` (containment), `RS.MI-02` (mitigation), `PR.AA-05` (auth assurance), `PR.DS-01` (data-at-rest protected), `RC.RP-01` (recovery executed). |
| **ISO 27001:2022** | A.5.24 (incident response planning), A.5.25 (incident assessment), A.8.5 (secure authentication), A.5.23 (security in supplier services — for the MSP context). |
| **CIS Controls v8.1** | Control 5 (Account Management), Control 6 (Access Control Management), Control 17 (Incident Response Management). |

## Related repo content

- **Detection:** [`T1078.004 Risky sign-in + mailbox-rule mutation`](../detections/kql/T1078.004_risky-signin-mailbox-rule.md).
- **Detection:** [`T1110.003 Entra password spray`](../detections/kql/T1110.003_entra-password-spray.md).
- **Threat intel:** [`AiTM phishing kits`](../threat-intelligence/ttps/aitm-phishing-kits.md) — the kit pattern that defeats MFA.
- **Threat intel:** [`Scattered Spider`](../threat-intelligence/actors/scattered-spider.md) — operationalizes this pattern at scale.
- **Hardening:** [`Entra ID Conditional Access baseline`](../hardening/entra-id.md) — prevention-side control set.

## References

- MITRE ATT&CK T1078.004: <https://attack.mitre.org/techniques/T1078/004/>
- Microsoft — Investigate risky users: search Microsoft Learn for "investigate risky users".
- Microsoft — Revoke user access in Entra ID: search Microsoft Learn for `Revoke-AzureADUserAllRefreshToken`.
- Microsoft — Audit OAuth app consents: search Microsoft Learn for "review permissions granted to apps".
