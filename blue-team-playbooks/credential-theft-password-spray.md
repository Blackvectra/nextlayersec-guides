# Playbook: Credential Theft / Password Spray

A response playbook for the most common identity-compromise pattern in Windows / Entra ID environments: an attacker enumerating valid usernames and spraying a small set of common passwords until something works, with the goal of riding a legitimate account into the tenant.

- **Author:** nextlayersec
- **Last updated:** 2026-06-08
- **Scope:** Microsoft 365 / Entra ID tenant + on-prem AD if hybrid. Adjust for AWS / GCP / Okta with the same shape but different log sources.

## Trigger

This playbook activates on any of:

- T1110.003 password-spray detection fires (see `detections/kql/T1110.003_entra-password-spray.md`).
- T1078.004 risky sign-in + mailbox-rule mutation fires (see `detections/kql/T1078.004_risky-signin-mailbox-rule.md`).
- T1021.001 RDP from unusual source fires with `B_SuccessAfterFails` set.
- Microsoft Defender Identity Protection raises a `UnfamiliarSignInProperties`, `MaliciousIPAddress`, or `PasswordSpray` risk event.
- A user reports "I got a sign-in MFA prompt I didn't request" or "I see unfamiliar sign-in activity in My Sign-ins".
- Defender for Cloud Apps raises `Risky sign-in` / `Mass download from cloud app` after an unfamiliar sign-in.

## Scope of the incident

Before responding, determine:

1. **Tier of the affected account** — regular user, helpdesk, IT admin, Global Admin, service account. Higher tier = faster response.
2. **Authentication source** — internet (B_External) vs internal (B_UnexpectedInt). External-source incidents almost always indicate stolen creds + remote attacker; internal-source incidents indicate an existing foothold.
3. **Single account or campaign** — pivot on the source IP / user-agent / `IsRisky` flag to identify whether this is one targeted account or a broader spray.
4. **MFA status** — was MFA enforced and bypassed (token theft / AiTM), or was MFA absent (legacy account)?

## Triage (first 15 minutes)

| # | Action | Tool / surface |
|---|---|---|
| 1 | Confirm the alert is not a false positive by pulling the matching SigninLogs / AuditLogs records and verifying the source IP and timing | Entra ID → Sign-ins, Defender XDR advanced hunting |
| 2 | Establish blast radius — how many accounts were targeted from the same source IP? | `SigninLogs \| where IPAddress == "<ip>" \| summarize count() by UserPrincipalName, ResultType` |
| 3 | Identify the highest-tier compromised account | Entra ID → Users → role memberships |
| 4 | Document the campaign signature — source IP(s), user-agent, target user list, attempted passwords if visible — into the case record | Internal incident tracker |
| 5 | Notify the affected user(s) of pending action (out-of-band — phone, NOT email) | — |

## Containment (next 30 minutes)

Containment goal: cut the attacker's access without destroying evidence.

### For each compromised account

1. **Revoke all sessions** — Entra ID → Users → [account] → Sessions → "Revoke all sessions". This invalidates every token issued, forcing re-authentication on every device.
2. **Force password change** at next sign-in. Reset to a temporary password communicated out-of-band.
3. **Force MFA re-enrollment** — Entra ID → Users → [account] → Authentication methods → "Require re-register MFA". Removes any AiTM-stolen tokens AND any attacker-added auth methods.
4. **Block sign-in** temporarily if the account is high-tier and not immediately needed for business operations. Better to call a Global Admin offline than to leave a possibly-compromised one active.
5. **Audit the account's authentication methods** — Entra ID → Users → [account] → Authentication methods. Any method the user didn't add (FIDO2 key, voice number, alternate email) is an attacker persistence mechanism. Remove it.
6. **Audit Conditional Access exclusions** — was the account on a CA exclusion list? Why? Remove if not justified.

### For the broader tenant

1. **Block the source IP** at the perimeter (firewall) AND in Entra ID Conditional Access (named location "Compromise — `<date>` — block").
2. **Block the user-agent string** if it's anomalous (curl, python-requests, common AiTM kit signatures).
3. **Lower the Conditional Access risk threshold** temporarily — escalate "medium" sign-in risk to "block" rather than "MFA challenge" for 24-48 hours while the campaign runs its course.
4. **Run a tenant-wide search** for the campaign signature: same source IP, same user-agent across `SigninLogs`. Add any new hits to the contained-accounts list and loop.

## Eradication (next 1-4 hours)

For each confirmed-compromised account:

1. **Audit `OWA` / `Exchange Online` inbox rules** — attacker-added rules forward / delete / hide replies. Hunt with `MailboxAuditLog` for `New-InboxRule` events from the contained accounts. The T1078.004 detection in `detections/kql/T1078.004_risky-signin-mailbox-rule.md` is exactly this signal.
2. **Audit OAuth / Application consents** the user granted — Entra ID → Users → [account] → Applications. Revoke any consent the user didn't intentionally grant. Investigate any consent matching the AiTM phishing-kit pattern in `threat-intelligence/ttps/aitm-phishing-kits.md`.
3. **Audit mailbox forwards** — `Get-Mailbox` `ForwardingAddress` / `ForwardingSmtpAddress`. Remove any unexpected forward.
4. **Audit recent SharePoint / OneDrive file shares** the user created — if compromised mid-business hours, attacker may have shared files externally.
5. **Audit Microsoft Teams** chats from the account during the compromise window — attackers use Teams for internal phishing pivots.
6. **Audit on-prem AD if hybrid** — `eventID 4624 LogonType=10` (RDP) and `eventID 4624 LogonType=3` (network) for the matching `samAccountName` during the compromise window.

For the broader tenant:

1. **Roll any service-account credentials** the user could have viewed (KeePass shares, password manager folders the user had access to, hardcoded creds in scripts they'd seen).
2. **Roll any API keys** for client systems the user managed (Microsoft Graph apps, Azure DevOps PATs, Power Platform connection references).

## Recovery (same day)

1. **Restore account access** with new credentials + freshly-enrolled MFA only after eradication steps complete.
2. **Sign-in monitoring** for 14 days — pin a SOC dashboard panel for the affected accounts: `SigninLogs | where UserPrincipalName == "<upn>" | where RiskState != "none"`.
3. **MFA challenge step-up** — apply a Conditional Access policy to the affected accounts requiring MFA + compliant device for 30 days.
4. **Communicate** — tell the user what happened, what was done, and what they should do (treat any password they used as exposed; rotate it everywhere).

## Lessons learned (week-after review)

Required output for every credential-theft incident, in the case-record file:

1. **Initial vector** — phishing, password spray, breach-data reuse, AiTM kit, etc.
2. **Why MFA didn't stop it** — wasn't enrolled, was bypassed via token theft, used phone-call MFA (phishable), etc.
3. **Why the Conditional Access policy didn't stop it** — gap in named location, exclusion that shouldn't have existed, etc.
4. **Time to detection** — when did the first event happen, when did the SOC see it?
5. **Time to containment** — sessions revoked, password reset, MFA re-enrolled.
6. **Time to eradication** — inbox rules removed, OAuth consents revoked.
7. **Baseline gap closed** — every credential-theft incident should produce at least one update to `hardening/nextlayersec-baseline.md` or the matching detection's tuning section.

## Framework mapping

| Framework | Mapping |
|---|---|
| **MITRE ATT&CK** | T1110.003 (Password Spraying), T1078.004 (Valid Accounts: Cloud), T1556 (Modify Authentication Process for the post-compromise persistence — added MFA methods, inbox rules), T1098.001 (Account Manipulation: Additional Cloud Credentials). |
| **NIST CSF 2.0** | `DE.CM-01` (network monitoring), `RS.MI-01` (incidents are contained), `RS.MI-02` (incidents are mitigated), `PR.AA-05` (auth assurance), `RC.RP-01` (recovery executed). |
| **ISO 27001:2022** | A.5.24 (incident response planning), A.5.25 (incident assessment), A.8.5 (secure authentication), A.8.11 (data masking — for the eradication step on viewed shared secrets). |
| **CIS Controls v8.1** | Control 5 (Account Management), Control 6 (Access Control Management), Control 17 (Incident Response Management). |

## Related repo content

- **Detection:** [`T1110.003 Entra password spray`](../detections/kql/T1110.003_entra-password-spray.md)
- **Detection:** [`T1078.004 Risky sign-in + mailbox-rule mutation`](../detections/kql/T1078.004_risky-signin-mailbox-rule.md)
- **Detection:** [`T1021.001 RDP from unusual source`](../detections/kql/T1021.001_rdp-unusual-source.md)
- **Threat intel:** [`Adversary-in-the-Middle phishing kits`](../threat-intelligence/ttps/aitm-phishing-kits.md) — the kit pattern that defeats MFA.
- **Threat intel:** [`Scattered Spider`](../threat-intelligence/actors/scattered-spider.md) — the actor profile that operationalizes this pattern at scale.
- **Hardening:** [`Entra ID Conditional Access baseline`](../hardening/entra-id.md) — the prevention-side control set.

## References

- MITRE ATT&CK T1110.003: <https://attack.mitre.org/techniques/T1110/003/>
- Microsoft — Investigate risky users: search Microsoft Learn for "investigate risky users".
- Microsoft — Revoke user access in Entra ID: search Microsoft Learn for "revoke-azureaduserallrefreshtoken".
