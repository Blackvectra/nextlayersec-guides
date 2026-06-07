# Hardening — Windows endpoint baseline

- **Author:** nextlayersec
- **Last updated:** 2026-06-07
- **Maturity:** published — baseline written, drawn from Microsoft Security Baselines + Defender ASR documentation + field rollout patterns; refine per fleet
- **Scope:** Windows 10/11 client and Windows Server 2019+ endpoint hardening — what every managed Windows device in a Microsoft 365 Business Premium / E3 / E5 fleet should have configured. Covers ASR, application control, LSA / credential protection, EDR baseline, BitLocker, Smart App Control, and tamper protection. **Does NOT cover** Conditional Access (see [`entra-id.md`](entra-id.md)), Intune compliance policy bodies (separate guide), or network-side hardening.
- **Prerequisites:**
  - Microsoft 365 **Business Premium** or higher (gets you Defender for Endpoint Plan 1 / 2 and Intune).
  - **Intune** as the management plane — every control below is deployable as an Intune configuration profile / endpoint security policy.
  - At least one device-compliance policy already in place (or willingness to create one as part of this rollout).
  - A **pilot ring** identified — 5–10 devices belonging to admins or IT, used to validate every step before broader deployment.

## Why this matters

Identity hardening (Entra ID / CA) stops the credential at the door. **Endpoint hardening is what catches the payload that already made it in** — through a click-through, a USB stick, a managed admin running something weird, an actual compromised account that landed on a workstation. Every detection in `detections/kql/` that targets endpoints (`T1003.001 LSASS`, `T1059.001 PowerShell`, `T1486 mass-rename ransomware`, `T1547.001 Run keys`) is **dependent on this baseline being in place** — without it, the payload has too many trivial ways to bypass the detection.

In ransomware-affiliate workflows (Scattered Spider et al.) the typical chain is:

```
Identity compromise   →   First hands-on-keyboard   →   LSASS / Run-key persistence   →   Lateral movement   →   Encryption
```

A solid endpoint baseline forces the attacker to fight every step. Without it, steps 2-4 are minutes of effort.

## The baseline

Numbered in **rollout order**. Each item is a single Intune endpoint-security policy or configuration profile.

### 1. `EDR — onboard Defender for Endpoint + tamper protection`

- **Purpose:** Get every device telemetry-onboarded into Defender XDR and lock the protections against attacker-disable.
- **Settings (Endpoint security → Antivirus + EDR):**
  - **EDR onboarding:** enabled (automatic via Intune)
  - **Tamper protection:** enabled
  - **Real-time protection:** enabled
  - **Cloud-delivered protection:** enabled (high cloud-block level)
  - **Sample submission:** Send safe samples automatically
  - **Behavior monitoring:** enabled
  - **PUA protection:** Block
- **Validation:** Device appears in Defender XDR → Endpoints → Device inventory within ~30 minutes. `DeviceTvmSecureConfigurationAssessment` table starts producing rows.

### 2. `EDR in block mode`

- **Purpose:** Have Defender's EDR-side detections actively block, not just alert.
- **Settings:** Defender portal → Settings → Endpoints → Advanced features → **EDR in block mode** = ON.
- **Validation:** Run an Atomic Red Team `T1059.001` PowerShell test on a pilot device. Defender should block the execution, not just alert.

### 3. `ASR — Attack Surface Reduction rules (the high-impact 8)`

Of the 17 ASR rules Defender supports, eight have the highest blast-radius reduction in field telemetry. Roll all eight at **Audit → Warn → Block** progression.

- **Settings (Endpoint security → Attack surface reduction policy):**
  - **`Block executable content from email client and webmail`** → Block
  - **`Block all Office applications from creating child processes`** → Block
  - **`Block Office applications from creating executable content`** → Block
  - **`Block Office applications from injecting code into other processes`** → Block
  - **`Block JavaScript or VBScript from launching downloaded executable content`** → Block
  - **`Block execution of potentially obfuscated scripts`** → Block
  - **`Block Win32 API calls from Office macros`** → Block
  - **`Block process creations originating from PSExec and WMI commands`** → Block (lateral-movement counter)
- **Rollout cadence:**
  - Week 1: deploy in **Audit** mode → watch `DeviceEvents` for `ActionType == "AsrAuditEvent"`
  - Week 2: review hits, allowlist legitimate cases, switch to **Warn**
  - Week 3: switch to **Block**
- **Validation:** `DeviceEvents | where ActionType startswith "Asr" | summarize count() by ActionType` — should see steady stream of audit/block events.

### 4. `LSA Protection (PPL) — credential theft mitigation`

- **Purpose:** Mark the LSASS process as **Protected Process Light (PPL)** so non-PPL processes can't open it. Directly counters Mimikatz / ProcDump-style credential dumping.
- **Settings:**
  - Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`
  - Push via Intune Settings Catalog → **Local Policies Security Options → Configure LSASS to run as a protected process**.
- **Validation:** Pair with the [`T1003.001 LSASS access`](../detections/kql/T1003.001_lsass-access-suspicious.md) detection — successful Mimikatz / ProcDump runs against LSASS should drop near-zero. Test with Atomic Red Team `T1003.001`.

### 5. `Credential Guard + Hypervisor-Enforced Code Integrity (HVCI)`

- **Purpose:** Move credential storage into a virtualization-isolated container that LSASS can't access directly. Counters NTLM relay + Pass-the-Hash.
- **Settings (Intune Settings Catalog → Windows Defender Credential Guard):**
  - **Credential Guard:** Enable with UEFI lock
  - **Virtualization-Based Security:** Enabled
  - **Secure Boot:** Required (prereq)
  - **HVCI / Memory Integrity:** Enable with UEFI lock
- **Caveat:** Some older drivers (vendor-specific) are HVCI-incompatible. Pilot ring before broad rollout. Check **System Information → Device Guard → Memory integrity disabled drivers** for compatibility.
- **Validation:** `msinfo32.exe` → "Virtualization-based security Services Running" should show "Credential Guard, Hypervisor enforced Code Integrity".

### 6. `BitLocker — full-disk encryption + recovery-key escrow`

- **Purpose:** Stolen / lost device data is unreadable. Recovery key in Entra ID (auto-escrowed) — not on a sticky note.
- **Settings (Endpoint security → Disk encryption policy):**
  - **OS drive encryption type:** XTS-AES 256-bit
  - **Encryption method:** XTS-AES 256-bit
  - **Require authentication at startup:** Yes
  - **Compatible TPM startup:** Required
  - **Save BitLocker recovery info to Entra ID:** Required
  - **Allow standard users to enable encryption:** Yes
- **Validation:** `manage-bde -status` on a device shows "Conversion Status: Fully Encrypted, Protection Status: Protection On". Recovery key visible in Entra → Devices → device → BitLocker recovery keys.

### 7. `Smart App Control (Windows 11) OR WDAC base policy (Windows 10 / Server)`

- **Purpose:** Application allowlisting — only signed code from reputable publishers (or your own signed binaries) runs.
- **Settings:**
  - **Windows 11 22H2+:** Enable **Smart App Control** at first boot (it cannot be enabled later — it's set during OOBE only). For existing fleets, this means waiting for the next refresh cycle.
  - **Windows 10 + Server:** Deploy a **WDAC base policy** in **Audit** mode (template: `AllowMicrosoft.xml` as starting point). Cycle through Audit → Warn → Enforce over 4–6 weeks.
- **Validation (WDAC):** `Microsoft-Windows-CodeIntegrity/Operational` event log → Events `3076` (audit block) / `3077` (would have been blocked). Review every audit event before flipping to enforce.
- **Trade-off:** WDAC is the highest-impact endpoint hardening *and* the highest-friction. The wrong rule blocks the line-of-business app. Pilot extensively. Worth it once dialed in — single-handedly stops most commodity ransomware.

### 8. `Network Protection — web content filtering + IP/URL block`

- **Purpose:** Block known-bad URLs and domains at the network layer before browser / process can even reach them. Includes Defender's TI feed of attacker infrastructure.
- **Settings (Endpoint security → Attack surface reduction):**
  - **Network protection:** Enabled (Block)
  - **Custom indicator support:** On (Settings → Endpoints → Advanced features)
- **Validation:** `DeviceNetworkEvents | where ActionType == "ConnectionBlockedByNetworkProtection"` — should see steady stream as users browse to known-bad domains.
- **Pair with:** The [`T1071.001 beacon-like outbound HTTPS`](../detections/kql/T1071.001_beaconing-rare-https.md) detection now has a backstop — Network Protection blocks the *known-bad* destination outright; the KQL detection catches the *unknown-but-fishy* destination.

### 9. `Controlled Folder Access — ransomware anti-tamper`

- **Purpose:** Protect Documents / Pictures / Videos / Music / OneDrive-synced folders from modification by untrusted processes. Ransomware encryptors are blocked from writing into these folders.
- **Settings:**
  - **Controlled folder access:** Block
  - **Protected folders:** default + any line-of-business document repositories on local disk
  - **Allow specific apps:** allowlist legitimate office apps / backup agents that need write access
- **Validation:** Test by running an Atomic Red Team `T1486` ransomware simulation in a pilot ring. Encryption attempts should fail with `DeviceFileEvents | where ActionType == "ControlledFolderAccessViolationBlocked"`.
- **Pair with:** [`T1486 mass file rename`](../detections/kql/T1486_mass-file-rename-ransomware.md) — the KQL fires if Controlled Folder Access is ever bypassed (file-rename pattern across many directories from a single process); CFA is the prevention, KQL is the detection-of-last-resort.

### 10. `PowerShell logging — module + script-block logging`

- **Purpose:** Capture every PowerShell command and script block on every endpoint. Feeds the detection pipeline. PowerShell is the LOLBin most attackers default to; without these logs, you can't detect anything.
- **Settings (Intune Settings Catalog → Administrative Templates → Windows Components → Windows PowerShell):**
  - **Turn on Module Logging:** Enabled, module names = `*`
  - **Turn on PowerShell Script Block Logging:** Enabled
  - **Turn on PowerShell Transcription:** Enabled (optional, high noise)
- **Validation:** `DeviceProcessEvents | where FileName == "powershell.exe" | summarize count()` should show non-zero. `Microsoft-Windows-PowerShell/Operational` event ID 4104 contains script-block content.
- **Pair with:** [`T1059.001 PowerShell encoded command`](../detections/kql/T1059.001_powershell-encoded-command.md).

## Rollout order

```text
Pre-flight (week 0):
  • Pilot ring identified (5-10 devices)
  • Intune-enrolled and Defender-onboarded as starting state
  • Communication plan to pilot users
  • Rollback plan documented per item

Stage 1 — Telemetry + base protection (week 1):
  1. EDR onboarding + tamper protection      ────┐
                                                 ├─ Foundational. Everything below assumes telemetry flowing.
  2. EDR in block mode                       ────┘

Stage 2 — Identity defense at the endpoint (week 2):
  4. LSA Protection (PPL)                    ────┐
                                                 ├─ Quick wins, low compatibility risk
  5. Credential Guard + HVCI                 ────┘  (HVCI may need driver review)

Stage 3 — Surface reduction (weeks 2-4, audit→warn→block):
  3. ASR rules — high-impact 8               (3-week audit→warn→block progression)

Stage 4 — Disk + network (week 3):
  6. BitLocker                                (rolls automatically; verify recovery-key escrow)
  8. Network Protection                       (low compatibility risk)

Stage 5 — Logging (week 3):
 10. PowerShell module + script-block logging (zero blast-radius, all detection upside)

Stage 6 — Anti-ransomware (week 4):
  9. Controlled Folder Access                 (test with simulated encryption in pilot)

Stage 7 — Application control (weeks 5-10, longest):
  7. Smart App Control (Win11) OR WDAC        (audit→warn→enforce, 4-6 weeks)
```

## Validation

Per-item validation specified above. For the **overall baseline**:

- **Microsoft Secure Score** (Defender XDR → Secure Score) should rise by ~40–80 points across the fleet over the rollout. Track week-over-week.
- **`DeviceTvmSecureConfigurationAssessment`** (Defender hunting table) — query per-control coverage:

    ```kql
    DeviceTvmSecureConfigurationAssessment
    | where IsApplicable == 1
    | summarize TotalDevices = count(),
                CompliantDevices = countif(IsCompliant == 1)
              by ConfigurationName
    | extend CompliancePct = round(100.0 * CompliantDevices / TotalDevices, 1)
    | sort by CompliancePct asc
    ```

- **Atomic Red Team validation suite** — run after Stage 6 in the pilot ring:
    - `T1003.001` (LSASS dump) — should be blocked by LSA-PPL + Defender + EDR-block
    - `T1059.001` (encoded PowerShell) — execution blocked by EDR-block, logged by script-block logging
    - `T1486` (file encryption pattern) — blocked by Controlled Folder Access
    - `T1547.001` (Run-key persistence) — Run-key write blocked by ASR / WDAC depending on the binary
- **Defender XDR Threat Analytics report** — every report has a "Recommended actions" tab; coverage % rises as you implement.

## Common pitfalls

1. **Skipping the pilot ring.** Every item in this baseline has bricked a fleet at some point in someone's career when rolled broadly without piloting. ASR Block-Win32-from-Office-macros + a finance team's macro-heavy spreadsheet = an angry director. Pilot.
2. **Enforcing WDAC without audit-mode runtime.** WDAC is the highest-impact and highest-friction item. Run audit mode 4-6 weeks and process every `3076` event in the CodeIntegrity log before flipping to enforce.
3. **Skipping Tamper Protection.** Without it, the first thing a sophisticated attacker does on a compromised endpoint is disable Defender. Tamper Protection blocks that even from local admin.
4. **Tamper Protection + EDR-in-block-mode rolled at the same time as ASR.** If something breaks, you can't tell which control did it. Stage the rollout per the order above.
5. **Forgetting service accounts / build agents.** WDAC and AppLocker policies must allowlist the build tooling on those hosts. A Jenkins agent under WDAC enforce mode that wasn't allowlisted = broken CI.
6. **BitLocker recovery keys NOT escrowed to Entra.** Hardware failure → data unrecoverable. Verify the policy enforces escrow before the device-side encryption kicks off.
7. **PowerShell transcription enabled tenant-wide.** Generates massive log volume. Module + script-block logging gives 90% of the value at 10% of the storage cost. Skip transcription unless you specifically need it.
8. **Assuming Smart App Control can be enabled on an existing fleet.** It only enables during OOBE — provisioning new devices. For existing Windows 11 devices, it's WDAC or wait for re-image.

## Reversal plan

Per-control reversal:

| Control | Reversal | Time to restore |
|---|---|---|
| EDR onboarding | Intune → offboard policy | hours |
| Tamper Protection | Defender portal → device action → disable tamper | minutes |
| EDR-in-block-mode | Settings toggle | seconds (tenant-wide) |
| ASR rules | Switch each rule to Audit mode | minutes |
| LSA-PPL | Registry value back to 0, reboot | minutes per device |
| Credential Guard / HVCI | Set to Disabled, reboot. **UEFI-locked variant requires physical access to clear the lock** | hours per device |
| BitLocker | Suspend protection per device; full decrypt is hours | hours per device |
| Smart App Control | Cannot reverse without re-imaging Windows 11 device | days |
| WDAC | Replace base policy with Allow-All policy, reboot | minutes |
| Network Protection | Switch to Audit | seconds (per device) |
| Controlled Folder Access | Switch to Audit | seconds (per device) |
| PowerShell logging | Disable Group Policy | minutes |

**Most reversible to least reversible:** Network Protection / CFA / EDR-block (instant toggles) → ASR (mode switch) → PowerShell logging → LSA-PPL → BitLocker / Credential Guard (driver / hardware dependency) → WDAC → **Smart App Control (effectively irreversible)**.

Pace your rollout accordingly. The least-reversible controls get the most pilot time.

## Framework mapping

- **MITRE ATT&CK mitigations:**
  - **M1040** Behavior Prevention on Endpoint (EDR-block, ASR, Network Protection, CFA)
  - **M1038** Execution Prevention (Smart App Control, WDAC, ASR)
  - **M1045** Code Signing (WDAC, Smart App Control)
  - **M1043** Credential Access Protection (LSA-PPL, Credential Guard)
  - **M1026** Privileged Account Management (HVCI, Credential Guard)
  - **M1041** Encrypt Sensitive Information (BitLocker)
  - **M1049** Antivirus / Antimalware (Defender base)
- **MITRE ATT&CK techniques significantly degraded:**
  - T1003.001 LSASS Memory → LSA-PPL + Credential Guard + Defender
  - T1059.001 PowerShell → EDR-block + ASR + script-block logging
  - T1486 Data Encrypted for Impact → Controlled Folder Access + Tamper Protection
  - T1547.001 Run Key Persistence → ASR + WDAC + EDR-block
  - T1218.* System Binary Proxy → ASR + WDAC
  - T1071.001 Web protocols (commodity C2) → Network Protection
  - T1078 Valid Accounts (post-compromise persistence on endpoint) → LSA-PPL + HVCI
- **NIST CSF 2.0:**
  - **PR.PS-01** Configuration management practices (all)
  - **PR.PS-05** Installation and execution of unauthorized software prevented (Smart App Control / WDAC, ASR)
  - **PR.DS-01** Data-at-rest protected (BitLocker)
  - **PR.AA-04** Identity assertions protected (LSA-PPL, Credential Guard)
  - **DE.CM-01** Networks and network services monitored (Network Protection telemetry)
  - **DE.CM-09** Computing hardware and software monitored (Defender base)
- **ISO 27001:2022:**
  - **A.8.7** Protection against malware (Defender, ASR, Network Protection)
  - **A.8.8** Management of technical vulnerabilities
  - **A.8.24** Use of cryptography (BitLocker)
  - **A.8.16** Monitoring activities
  - **A.8.20** Network security
- **CIS Controls v8.1:**
  - **2** Inventory and Control of Software Assets (WDAC / Smart App Control)
  - **3** Data Protection (BitLocker)
  - **8** Audit Log Management (PowerShell logging)
  - **9** Email and Web Browser Protections (ASR Office rules, Network Protection)
  - **10** Malware Defenses (Defender + Tamper Protection)
  - **12.6** Use of Secure Network Protocols
  - **13** Network Monitoring

## Related repo content

- Hardening (sibling): [`entra-id.md`](entra-id.md) — identity-side baseline; pair with this for the full front-line stack
- Detections (Windows endpoint): [`T1003.001 LSASS`](../detections/kql/T1003.001_lsass-access-suspicious.md), [`T1059.001 PowerShell`](../detections/kql/T1059.001_powershell-encoded-command.md), [`T1486 mass file rename`](../detections/kql/T1486_mass-file-rename-ransomware.md), [`T1547.001 Run-key persistence`](../detections/kql/T1547.001_runkey-persistence.md), [`T1071.001 beacon-like HTTPS`](../detections/kql/T1071.001_beaconing-rare-https.md)
- Playbook: [`Ransomware outbreak`](../blue-team-playbooks/ransomware-outbreak.md)
- Framework: [`NIST CSF 2.0`](../frameworks/nist-csf.md)

## References

- **Microsoft Security Baselines** for Windows 10/11 — Security Compliance Toolkit. <https://learn.microsoft.com/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines>
- **Microsoft Defender for Endpoint ASR rules deployment guide** — Microsoft Learn → "Attack surface reduction rules deployment overview".
- **Microsoft Defender Application Control (WDAC)** docs — Microsoft Learn → "Application Control for Windows".
- **CISA Microsoft 365 Secure Configuration Baselines** — published by CISA / ScubaGear. <https://github.com/cisagov/ScubaGear>
- **Atomic Red Team** — validation suite reference. <https://github.com/redcanaryco/atomic-red-team>
- **Olaf Hartong's sysmon-modular** — supplementary Sysmon logging if Defender telemetry alone isn't enough. <https://github.com/olafhartong/sysmon-modular>
