# TTP roundup: Adversary-in-the-Middle (AiTM) phishing kits

- **MITRE ATT&CK:** T1557 – Adversary-in-the-Middle; T1606.002 – Web Session Cookie forgery / theft; T1078.004 – Valid Accounts: Cloud Accounts (post-success); T1556.006 – MFA bypass via session-token theft.
- **Last updated:** 2026-06-04

## What it is

**Adversary-in-the-Middle (AiTM)** phishing kits proxy the legitimate sign-in flow between the victim and the real identity provider (Microsoft Entra ID, Okta, Google Workspace). The kit intercepts credentials *and* the post-MFA session cookie. Because the attacker captures a valid token rather than a static credential, **MFA based on push, SMS, voice, or TOTP does not stop the attack** — the victim genuinely completes the MFA challenge and the attacker rides the resulting session.

The technique was popularized by the **evilginx2** and **Modlishka** open-source frameworks and weaponized by commercial phishing-as-a-service operations (Caffeine, Tycoon 2FA, Mamba 2FA, NakedPages, Greatness, Storm-1575). Microsoft documented large-scale AiTM campaigns in 2022 ("AiTM phishing campaign followed by BEC") and again in 2024–2025 against high-value M365 tenants.

## How it works

```
Victim ──HTTPS──▶  AiTM kit  ──HTTPS──▶  Real IdP (login.microsoftonline.com / Okta)
                  (reverse-                ▲
                   proxies                 │
                   the auth flow)          │
                                           ▼
                  ──── captures ───────  session cookie
                       credentials       (ESTSAUTH / okta.session)
                       + MFA response    + refresh token
```

1. Victim clicks a link in a phishing email pointing to an attacker-controlled domain that mimics the IdP (`login-microsft-com-xxx.online`, `okta-sso-prod.[bad].com`).
2. AiTM kit reverse-proxies every byte to and from the real IdP.
3. Victim sees the genuine IdP login page (because they're really talking to it), enters credentials, completes MFA.
4. Real IdP issues a session cookie + refresh token. The kit intercepts both, strips them out of the response, and replays them in the attacker's browser.
5. Attacker is now logged in **as the victim, post-MFA**, often without any "new device" or "risky sign-in" trigger because the IP, user agent, and session story all look continuous.

## Who uses it

Recent public reporting (2024–2026):

- **Scattered Spider / UNC3944 / Octo Tempest** — pairs AiTM with help-desk social engineering. See the [Scattered Spider profile](../actors/scattered-spider.md).
- **Storm-1575 (Microsoft tracking)** — pure financial-motive M365 takeover for BEC and gift-card fraud.
- **Storm-1167** — commodity Tycoon-2FA-as-a-service operation.
- **FIN7 / Sangria Tempest** — used AiTM as initial access for follow-on extortion in 2024–2025.
- Numerous unattributed actors using the kit-rental market.

## How to detect it

### Telemetry needed

- **Entra ID `SigninLogs`** — required (`AADCloudAppEvents`, `SigninLogs`, `AADRiskyUsers`).
- **`AADNonInteractiveUserSignInLogs`** — token-refresh activity hides here.
- **Mailbox audit / `OfficeActivity`** — for the post-takeover mailbox-rule creation that always follows.
- **Defender for Cloud Apps** if available — surfaces `Impossible travel`, `Activity from infrequent country`, `Unusual ISP`.

### High-fidelity signals

1. **Sign-in succeeds → mailbox rule created within minutes.** Attacker's first move is usually a `move-to-RSS-Feeds / delete-after-N-days` rule that hides replies to their fraud emails. Detection idea: correlate `Entra successful sign-in` with `Set-InboxRule` from the same user within ≤ 10 minutes. (See backlog item `T1078.004 — Entra risky sign-in + mailbox-rule creation` in `TODO.md`.)
2. **Session-token reuse from a new geo/ASN within hours of sign-in.** The original session is from victim IP; the replayed session is from VPS / residential-proxy IP. `SigninLogs | where ResultType == 0 and ConditionalAccessStatus == "success" | join non-interactive on CorrelationId` and compare `IPAddress` between hops.
3. **OAuth consent grants to an unknown app right after sign-in.** Attackers sometimes plant a malicious OAuth app to persist after the stolen cookie expires.
4. **Risky sign-in with `AuthenticationDetails` showing `success` for the proxied IP**, even when no actual MFA prompt is logged on the user's device.
5. **Cookie reuse from non-compliant device.** `DeviceDetail.isCompliant == false` and `DeviceDetail.trustType in (null, "")` while the rest of the sign-in looks normal.

### Existing detections in this repo

- [`T1110.003_entra-password-spray`](../../detections/kql/T1110.003_entra-password-spray.md) — pre-AiTM credential probing.
- [`T1071.001_beaconing-rare-https`](../../detections/kql/T1071.001_beaconing-rare-https.md) — useful for catching the attacker's post-access C2.

### Detections worth adding

- T1078.004 — risky sign-in followed by mailbox-rule creation (in TODO).
- T1539 — session cookie reuse anomaly (high-fidelity in Defender XDR via `IdentityInfo` + `SigninLogs`).
- T1556.006 — successful sign-in where `AuthenticationDetails` shows MFA satisfied by an *uncommon* method or by token replay.

## How to mitigate

### Hard prevention (kills the technique)

- **Phishing-resistant MFA for everyone with privileges, then everyone.** FIDO2 security keys, Windows Hello for Business, certificate-based authentication, passkeys. These bind the credential to the legitimate IdP origin via WebAuthn — the AiTM proxy domain fails origin validation and the authenticator refuses to release the assertion.
- **Disable weakened MFA methods** in Entra ID: SMS, voice call, OATH-TOTP-only configurations.
- **Enforce `requireAuthenticationStrength: phishingResistantMfa`** in Conditional Access for at least: Global Admin, Application Admin, Privileged Role Admin, Privileged Authentication Admin, Cloud Application Admin, Exchange Admin, SharePoint Admin, Helpdesk Admin.

### Soft prevention (raises the bar)

- **Conditional Access "compliant device" requirement** — token is bound to a registered, compliant device, making cookie replay much harder.
- **Continuous Access Evaluation (CAE)** — shrinks the window of useful stolen tokens (≤ 5 minutes from a CAE event vs hours from a refresh token).
- **Named locations + risk-based CA policies** — block sign-ins from anonymous proxies, TOR exits, and unfamiliar countries.
- **Token Protection (preview as of late 2025)** — binds the token to the originating device.
- **Anti-phishing email rules** — Defender for Office 365 Safe Links + impersonation protection + heuristic catches on look-alike IdP domains.
- **Educate users** to verify the URL bar shows `login.microsoftonline.com` (or your tenant's federation URL) *exactly*. AiTM domains always have something different.

### Containment when AiTM succeeds

1. **Revoke all sign-in sessions** for the user: `Revoke-AzureADUserAllRefreshToken` or Graph `revokeSignInSessions`.
2. **Reset the user's password** AND require MFA re-enrollment with a phishing-resistant method.
3. **Hunt and remove any mailbox rules** the attacker created (almost certain).
4. **Hunt and revoke OAuth consent grants** the attacker added (`Get-MgUserOauth2PermissionGrant`).
5. **Review and revoke any service-principal additions** done by the user during the compromise window.
6. **For privileged users, rotate downstream secrets** (Azure key-vault access, Entra app secrets the user could have read).

## Framework mapping

- **MITRE ATT&CK:** T1557 (AiTM), T1606.002 (Web Session Cookie), T1078.004 (Cloud Accounts), T1556.006 (MFA bypass), T1539 (Steal Web Session Cookie).
- **NIST CSF 2.0:** PR.AA-04 (Identity assertions are protected, conveyed, and verified); PR.AA-05 (Access permissions / entitlements managed); DE.CM-06 (External provider activity monitored); RS.MI (Mitigations executed).
- **NIST SP 800-63B-4:** AAL3 for privileged identities (phishing-resistant authentication required).
- **ISO 27001:2022:** A.5.17 (Authentication information); A.8.5 (Secure authentication).

## References

- Microsoft Threat Intelligence — "AiTM phishing campaign and BEC" (2022); "Octo Tempest" (2023–2025).
- CISA Joint Advisory **AA23-320A** on Scattered Spider — calls out AiTM in detail.
- evilginx project — defender-side documentation: <https://github.com/kgretzky/evilginx2>
- Modlishka project — research-only: <https://github.com/drk1wi/Modlishka>
- Microsoft Learn — "Conditional Access: Require phishing-resistant MFA" (search Microsoft Learn).
- OWASP — Web Session Cookie theft guidance.
