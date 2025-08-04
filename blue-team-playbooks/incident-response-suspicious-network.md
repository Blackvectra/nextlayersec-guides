# Incident Response Playbook: Suspicious Network Activity

## Overview

This playbook guides Security Operations Center (SOC) analysts through the detection, investigation, and response steps for suspicious network activity potentially indicating lateral movement, data exfiltration, or internal reconnaissance.

---

## Objectives

- Detect unusual network behaviors using SIEM and network monitoring tools  
- Investigate alerts with context and enrichment  
- Contain and remediate malicious activity  
- Document the incident for lessons learned and compliance  

---

## Detection

### Indicators to Watch For

- Unusual or unauthorized internal scanning activity  
- Unexplained spikes in outbound traffic volume  
- Connections to rare or suspicious external IP addresses  
- Use of uncommon protocols or ports within the network  

### Detection Tools

- SIEM (e.g., Splunk, QRadar, Microsoft Sentinel)  
- Network IDS/IPS (e.g., Suricata, Snort)  
- Endpoint Detection and Response (EDR) tools  
- NetFlow and packet capture analysis  

---

## Investigation

1. **Verify Alert Details**  
   - Confirm the source, destination IPs, time, and protocol.  
   - Cross-reference with asset inventory and user roles.

2. **Collect Contextual Data**  
   - Query endpoint logs for process and user activity.  
   - Check authentication logs for unusual logins.  
   - Review firewall and proxy logs.

3. **Determine Scope and Impact**  
   - Identify affected systems and data.  
   - Assess if data exfiltration or malware is present.

---

## Response

1. **Containment**  
   - Isolate compromised hosts from the network.  
   - Block malicious IP addresses or domains.

2. **Eradication**  
   - Remove malware or unauthorized tools.  
   - Patch exploited vulnerabilities.

3. **Recovery**  
   - Restore systems from clean backups if necessary.  
   - Monitor closely for re-infection.

---

## Documentation & Reporting

- Record timelines, actions taken, and findings.  
- Communicate incident status to stakeholders.  
- Update detection rules and response procedures as needed.

---

## Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)  
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/incident-handlers-handbook/)  
- [CISA Cyber Essentials](https://www.cisa.gov/cyber-essentials)  

---

> _“Detect early, respond decisively, and learn continuously.”_  
> — Blackvectra

