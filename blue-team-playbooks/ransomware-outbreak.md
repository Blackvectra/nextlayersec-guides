# Playbook: Ransomware Outbreak

- **Author:** nextlayersec
- **Last updated:** 2026-06-02
- **Severity default:** Critical
- **Owner role:** IR Lead (with SOC Tier 2/3 support); CISO informed within 15 minutes; legal + comms engaged within 1 hour

## Trigger

Any of:

- [`detections/kql/T1486_mass-file-rename-ransomware`](../detections/kql/T1486_mass-file-rename-ransomware.md) — mass file rename on a host (the encryption fan-out signal).
- User-reported ransom note (`!_INFO_!.txt`, `HOW_TO_DECRYPT.html`, desktop wallpaper change).
- EDR alert: shadow-copy deletion (`vssadmin.exe delete shadows`, WMI `Win32_ShadowCopy`), Windows backup catalog wipe, BCD recovery disabling (`bcdedit /set recoveryenabled No`), `wbadmin delete catalog`.
- Endpoint encryption observed by file-integrity monitoring (unusually high write rate across many directories).
- Backup tool reports "files modified after snapshot" anomaly.
- Third-party notification (CISA, ISAC, MSP/MSSP, partner) of confirmed infection upstream.

## Scope

This playbook covers an **active or imminent ransomware encryption event** — from first detection of in-progress encryption through containment, eradication, and recovery. It does NOT cover:

- Pre-encryption stages (initial access, persistence, lateral movement) once they're confirmed but not yet encrypting → use the [phishing-email-triage](phishing-email-triage.md) or (planned) cred-theft / lateral-movement playbooks first.
- Negotiation, ransom payment decision, or insurance claim — out of scope for SOC; engage IR retainer / legal / executive leadership.
- Cloud-only / SaaS data-encryption events (e.g., compromised Microsoft 365 with mailbox-rule wiper) → use the (planned) cloud-compromise playbook.

## Triage (first 15 minutes — decisions matter more than perfection)

1. **Confirm it's ransomware, not destructive wiper or test.**
   - Are user files showing a new extension? Is there a ransom note?
   - Compare current file extensions against a known-good baseline.
2. **Scope the active blast radius.**
   - How many hosts are showing the encryption signal? (`DeviceFileEvents | where ActionType == "FileRenamed" | summarize count() by DeviceName, bin(Timestamp, 5m)`).
   - Are any file shares or backup servers affected?
3. **Identify the actor's likely access vector** (if obvious): RDP exposed, recent phishing → credential theft → lateral movement, vendor supply chain, etc. Don't get stuck here — this is for prioritizing containment.
4. **Snapshot the active alert state** (Defender XDR, Sentinel, your ticketing system) — anything you'll want for the post-mortem.
5. **Declare the incident.** Notify IR lead → CISO → on-call exec. Open a war-room channel.

## Containment (next 30 minutes — speed > elegance)

### Network

- **Isolate affected hosts via EDR.** Do NOT shut down or log off — preserve memory and live process state for forensics.
- **Disconnect file shares.** Stop the SMB service on file servers showing write activity; remove writable SMB exports. Block SMB (TCP 445) and RPC (TCP 135) at internal segmentation boundaries.
- **Quarantine the network segment** if encryption is spreading laterally. Switch port shutdown / NAC quarantine VLAN if available.
- **Block egress** for any C2 destinations the attacker may be controlling — see [`T1071.001_beaconing-rare-https`](../detections/kql/T1071.001_beaconing-rare-https.md).

### Identity

- **Disable every account** that has logged into an affected host in the last 7 days (`SigninLogs | where DeviceName in (...)`).
- **Force password reset + MFA re-enroll** for every disabled account.
- **Revoke refresh tokens** across Entra ID: `Revoke-AzureADUserAllRefreshToken` or Graph `revokeSignInSessions`.
- **Rotate any service-account credentials** that an affected host could read (DPAPI / LSASS dumps). If LSASS access was observed, see [`T1003.001_lsass-access-suspicious`](../detections/kql/T1003.001_lsass-access-suspicious.md) — assume every credential on that host is compromised.
- **Rotate the krbtgt account password twice** (with a 10-hour gap) if domain controllers were affected or LSASS dumping happened on a DC. This invalidates outstanding Kerberos tickets including Golden Ticket forgery.

### Data / Backups

- **Protect backups immediately.** Disconnect backup servers from the network if possible; verify the backup catalog is intact and offline copies exist. Modern ransomware affiliates target backups first.
- **Snapshot critical systems** (databases, identity stores) in their current state — even if encrypted — to a separate, isolated storage location. You may need them for forensics or for partial decryption attempts.
- **Halt ongoing backup jobs** writing to network targets — they may be copying encrypted files over good ones.

## Eradication

1. **Identify the ransomware family.** Submit a sample (encrypted file + ransom note) to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) or MalwareBazaar. Family identification informs whether a known decryptor exists ([NoMoreRansom](https://www.nomoreransom.org/)).
2. **Map the persistence footprint.**
   - Scheduled tasks: `schtasks /query /v /fo csv`
   - Services: new services in last 30 days; ones running from `\Users\*`, `\ProgramData\*`, `\Temp\*`.
   - Run keys: see [`T1547.001_runkey-persistence`](../detections/kql/T1547.001_runkey-persistence.md).
   - WMI subscriptions: `Get-WmiObject -Namespace root/Subscription -Class __EventFilter|__EventConsumer|__FilterToConsumerBinding`.
3. **Hunt for staging tooling** the attacker left behind — RMM agents (AnyDesk, ScreenConnect, RustDesk, Splashtop), tunnels (ngrok, Cloudflared, Chisel), credential dumpers, exfil tools.
4. **Rebuild rather than clean** for any host that was the encryption *source* (the process that ran the encryption — identified via [`T1486_mass-file-rename-ransomware`](../detections/kql/T1486_mass-file-rename-ransomware.md)) or that was confirmed to have had attacker hands-on-keyboard activity. Cleaning post-encryption hosts is not safe.
5. **Patch + harden** the access vector before bringing anything back online — patches, MFA enforcement, conditional access tightening, RDP exposure removal.

## Recovery

1. **Restore from offline / immutable backups** to clean, rebuilt hosts. Do NOT restore to compromised hosts.
2. **Bring back the smallest necessary services first** (identity, DNS, file shares for the highest-value teams) and verify integrity at each step.
3. **Re-enable accounts** with new credentials and MFA. Audit privileged-group memberships post-restore — attackers often add themselves to Domain Admins / Global Admins.
4. **Increase detection fidelity** for the affected user/host populations for at least 30 days — the original access vector often regenerates if not fully eradicated.
5. **Comms.** Coordinate user-facing communication with legal and exec. Be specific about what data was / wasn't affected; vague messaging erodes trust.

## Lessons learned (within 14 days post-incident)

- **Detection gaps.** Did `T1486` fire on time? If not, why — telemetry missing, threshold too high, signal lost in noise?
- **Containment time.** How long from first encryption event to network isolation? Aim for < 10 minutes; document what slowed you down.
- **Backup posture.** Were backups offline / immutable? Did the attacker reach them? File a remediation ticket for any "no" answer.
- **Initial access vector.** Was there a missed signal? File detections for it.
- **Tabletop next quarter.** Run this playbook as a tabletop with a new wrinkle (e.g., backup admin's account is the one compromised).

## Framework mapping

- **MITRE ATT&CK:** T1486 – Data Encrypted for Impact; T1490 – Inhibit System Recovery; T1489 – Service Stop; T1485 – Data Destruction; T1078 – Valid Accounts (post-access); T1003.001 – LSASS Memory (pre-encrypt cred theft); T1071.001 – Web Protocols (C2).
- **NIST CSF 2.0:** RS.MA (Incident management); RS.AN (Analysis); RS.CO (Communication); RS.MI (Mitigation); RC.RP (Recovery Plan); RC.IM (Improvements); PR.DS-11 (Backups maintained, tested, and protected).
- **NIST SP 800-61r2 phase:** Containment → Eradication → Recovery → Post-Incident.
- **ISO 27001:2022:** A.5.24 – A.5.27 (Incident management); A.5.30 (ICT readiness for business continuity); A.8.13 (Information backup).

## Related content

- Detection: [`T1486_mass-file-rename-ransomware`](../detections/kql/T1486_mass-file-rename-ransomware.md) — the primary trigger.
- Detection: [`T1003.001_lsass-access-suspicious`](../detections/kql/T1003.001_lsass-access-suspicious.md) — pre-encrypt credential theft.
- Detection: [`T1547.001_runkey-persistence`](../detections/kql/T1547.001_runkey-persistence.md) — persistence footprint.
- Detection: [`T1071.001_beaconing-rare-https`](../detections/kql/T1071.001_beaconing-rare-https.md) — C2 channel.
- Threat-intel: [`Scattered Spider`](../threat-intelligence/actors/scattered-spider.md) — common ransomware affiliate using the TTP chain that triggers this playbook.

## External references

- CISA `#StopRansomware` joint advisories: https://www.cisa.gov/stopransomware
- No More Ransom decryptor index: https://www.nomoreransom.org/
- ID Ransomware (family identification): https://id-ransomware.malwarehunterteam.com/
- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
