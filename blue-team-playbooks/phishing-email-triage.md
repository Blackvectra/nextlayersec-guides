# Playbook: Phishing Email Triage

- **Author:** nextlayersec
- **Last updated:** 2026-05-27
- **Severity default:** Medium (raise to High on confirmed credential entry or attachment execution)
- **Owner role:** SOC Tier 1 → escalate to Tier 2 / IR Lead on confirmed compromise

## Trigger

Any of:

- User-reported phish (Outlook "Report Phishing" / Defender submission / ticket).
- Automated detection: Defender for Office 365 alert, mail-flow rule, sandbox detonation verdict.
- Threat intel match on sender, URL, or attachment hash.
- Sibling detection fired: suspicious sign-in, OAuth consent, or Entra risky user shortly after user opened email.

## Scope

This playbook covers triage and response for **inbound phishing email**: credential harvesting, malware delivery, and BEC pretexting up to the point of user interaction. It does **not** cover:

- Post-compromise account takeover → use the (planned) BEC and cloud-account-compromise playbooks.
- Outbound phish (compromised internal account sending) → use the BEC playbook.
- SMS / voice phishing → use the (planned) smishing/vishing playbook.

## Triage (first 15 minutes)

1. **Validate the report.**
   - Pull the original message: headers, body, attachments, links. Use Defender → Email Entity or Graph `/messages` for a forensic copy.
   - Confirm it actually arrived (the user did not forward a screenshot of something quarantined elsewhere).

2. **Capture initial artifacts.**
   - **Sender:** display name, `From:`, `Return-Path:`, `Authentication-Results` (SPF / DKIM / DMARC verdicts).
   - **Subject + body:** copy to incident notes (never reply to the message).
   - **Links:** every URL, including redirector chain. Resolve final destination in a sandbox — never on an analyst workstation.
   - **Attachments:** SHA-256 only. Detonate in a sandbox (any.run, Joe Sandbox, MDO Safe Attachments). Do not download to your laptop.
   - **Recipients:** all delivered mailboxes — this is the blast radius.

3. **Classify intent.**
   - Credential harvest (link → fake login page)
   - Malware delivery (attachment / link to payload)
   - BEC / pretext (no payload — pure social engineering toward a wire or gift card)
   - Reconnaissance (tracking pixel, "is this email valid")

4. **Decide severity.**
   - Any user clicked the link → **High**.
   - Any user submitted credentials → **High**, also raise IR.
   - Any user opened the attachment → **High**, also raise IR.
   - Email blocked or quarantined for all recipients with no clicks → **Low**.

## Containment

1. **Purge the message across the tenant.**
   - Defender for Office 365: Threat Explorer → Take action → Move to Junk / Soft delete / Hard delete for all recipients.
   - On-prem Exchange: `Search-Mailbox -DeleteContent` (preserve evidence first).

2. **Block the indicators.**
   - Sender domain / IP → tenant block list and edge mail gateway.
   - URL(s) → SafeLinks block list, web proxy / DNS sinkhole.
   - Attachment SHA-256 → EDR block, MDO custom indicator.

3. **If a user clicked a credential page:**
   - Disable the user's sign-in and revoke all refresh tokens (`Revoke-AzureADUserAllRefreshToken` / Graph `revokeSignInSessions`).
   - Force password reset and re-enroll MFA.
   - Hunt for impossible-travel / unfamiliar-location sign-ins in `SigninLogs` over the previous 24h.

4. **If a user opened an attachment:**
   - Isolate the endpoint via EDR.
   - Pull the parent process tree and outbound network connections from `DeviceProcessEvents` and `DeviceNetworkEvents`.
   - Pivot on the document → child process chain (Office → PowerShell / mshta / rundll32 is high-fidelity).

## Eradication

- Remove the message from all mailboxes (verify with a follow-up search).
- Remove any persistence the payload established: scheduled tasks, run keys, WMI subscriptions, OAuth grants, mailbox rules.
- Rotate every secret the affected user could reach (service principals, app passwords, stored creds in vault).
- If the payload reached a server / shared host: reimage rather than clean.

## Recovery

- Re-enable the user account with MFA enforced and a password the user has never used.
- Restore any data the user lost from backup (do not restore from a snapshot taken after compromise).
- Increase alerting fidelity for the affected user / host for 14 days.

## Lessons learned

- Was the email blocked by SPF / DKIM / DMARC? If not, why — and what tenant policy change closes the gap?
- Did SafeLinks / Safe Attachments detonate it? If not, file a vendor escalation.
- Did the user report it via the official button? If not, run a refresher and verify the button is deployed in the affected OU.
- Update this playbook with anything that surprised you.

## Framework mapping

- **MITRE ATT&CK:** T1566 – Phishing; T1566.001 – Spearphishing Attachment; T1566.002 – Spearphishing Link; T1078.004 – Valid Accounts: Cloud Accounts (if creds entered).
- **NIST CSF 2.0:** RS.MA (Incident management); RS.AN (Analysis); RS.MI (Mitigation); PR.AT (Awareness, for the lessons-learned loop).
- **NIST SP 800-61r2 phase:** Detection & Analysis → Containment / Eradication / Recovery → Post-Incident.
- **ISO 27001:2022:** A.5.24 – A.5.27 (Incident management); A.6.3 (Awareness).

## References

- Related detections:
  - [`detections/kql/T1110.003_entra-password-spray.kql`](../detections/kql/T1110.003_entra-password-spray.md) — frequent follow-on for credential-harvest phish.
  - [`detections/kql/T1059.001_powershell-encoded-command.kql`](../detections/kql/T1059.001_powershell-encoded-command.md) — common payload behavior after attachment open.
- Related workflow: [`detection-workflows/`](../detection-workflows/) — phishing email triage workflow (planned).
- Microsoft Learn — search for "Defender for Office 365 Threat Explorer remediation".
- MITRE ATT&CK Phishing: https://attack.mitre.org/techniques/T1566/
