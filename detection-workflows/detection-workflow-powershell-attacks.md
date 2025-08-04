# Detection Workflow: PowerShell-based Attacks

## Overview

PowerShell is a powerful Windows scripting tool frequently abused by attackers for executing malicious commands, bypassing security controls, and performing lateral movement. This workflow outlines how Security Operations Center (SOC) analysts can detect, investigate, and respond to suspicious PowerShell activity.

---

## Objectives

- Identify anomalous PowerShell usage  
- Analyze suspicious commands and scripts  
- Contain and remediate potential compromise  
- Enhance detection rules for future threats  

---

## Detection Techniques

### Key Indicators of PowerShell Abuse

- PowerShell process launching without a user interface (hidden or encoded commands)  
- Use of encoded commands (e.g., `-EncodedCommand`) or Base64 strings  
- PowerShell executing from unusual parent processes (e.g., `wmiprvse.exe`, `rundll32.exe`)  
- Downloading or executing scripts from external URLs  
- PowerShell spawned by non-administrative users for suspicious tasks  

### Detection Sources

- Windows Event Logs ([Event ID 4104: PowerShell Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_script_block_logging))  
- Sysmon logs ([Event ID 1: Process Creation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon))  
- Endpoint Detection and Response (EDR) alerts  
- Network traffic to suspicious URLs  

---

## Investigation Steps

1. **Validate Alert**  
   - Confirm the event ID and command line arguments.  
   - Decode any Base64 or encoded strings.

2. **Analyze Parent-Child Process Relationship**  
   - Identify which process spawned PowerShell.  
   - Look for anomalies (e.g., `services.exe` spawning PowerShell).

3. **Correlate with Other Events**  
   - Check for concurrent suspicious activity (file downloads, registry changes).  
   - Cross-reference with authentication logs for unusual user activity.

4. **Identify the Scope**  
   - List affected endpoints and user accounts.  
   - Assess lateral movement or data access attempts.

---

## Response Actions

1. **Containment**  
   - Isolate compromised endpoints.  
   - Block malicious URLs and IPs in firewall/proxy.

2. **Eradication**  
   - Remove malicious scripts and binaries.  
   - Kill suspicious PowerShell processes.

3. **Recovery**  
   - Restore systems to known good state.  
   - Apply patches and security updates.

4. **Enhance Detection**  
   - Update SIEM detection rules for PowerShell abuse.  
   - Enable/strengthen PowerShell logging policies.

---

## References

- [Microsoft PowerShell Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_script_block_logging)  
- [Sysmon Download and Configuration](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)  
- [MITRE ATT&CK: PowerShell (T1086)](https://attack.mitre.org/techniques/T1086/)  
- [Detecting PowerShell Attacks with Sysmon (SANS Whitepaper PDF)](https://www.sans.org/white-papers/39864/detecting-powershell-attacks-with-sysmon-38169)  

---

> _“Visibility is the first step toward control. Monitor PowerShell closely.”_  
> — Blackvectra
