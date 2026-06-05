# Blue Team & IR Tools (Curated)

Fast links you’ll actually use day‑to‑day.

## Triage & Analysis
- **CyberChef** — swiss‑army data transforms: https://gchq.github.io/CyberChef/
- **VirusTotal** — file/URL analysis: https://www.virustotal.com/
- **Hybrid Analysis** — sandboxing: https://www.hybrid-analysis.com/
- **Any.Run** — interactive malware sandbox: https://any.run/

## Intel & Exposure
- **Have I Been Pwned** — breach lookup: https://haveibeenpwned.com/
- **Shodan** — internet‑exposed assets: https://www.shodan.io/
- **CISA KEV** — known exploited vulns: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Network / Email / DNS
- **MXToolbox** — DNS/SMTP checks: https://mxtoolbox.com/
- **Wireshark** — packet analysis: https://www.wireshark.org/

## Identity & Cloud Attack Analysis

Identity is the new perimeter — most ransomware affiliates today (including [Scattered Spider](../threat-intelligence/actors/scattered-spider.md)) live in Entra ID, Okta, and connected SaaS. These tools surface the abuse.

- **ROADtools** — offline Entra ID / Azure AD enumeration and graph analysis: https://github.com/dirkjanm/ROADtools
- **AzureHound + BloodHound CE** — attack-path mapping for Azure / Entra ID: https://github.com/SpecterOps/BloodHound + https://github.com/BloodHoundAD/AzureHound
- **ScubaGear (CISA)** — Microsoft 365 / Entra security baseline assessment: https://github.com/cisagov/ScubaGear
- **Monkey365** — M365 / Entra audit and threat hunting: https://github.com/silverhack/monkey365
- **Hawk** — M365 incident-response forensic toolkit (mailbox rules, OAuth grants, sign-ins): https://github.com/T0pCyber/hawk
- **365Inspect** — read-only M365 security review: https://github.com/soteria-security/365Inspect
- **AADInternals** — Entra ID / hybrid-identity research toolkit: https://aadinternals.com/aadinternals/
- **Sentinel + Defender XDR advanced hunting** — query language reference: search Microsoft Learn for "KQL quick reference" and "Defender XDR tables".

## Endpoint Triage & Memory

- **KAPE (Kroll Artifact Parser/Extractor)** — fast targeted endpoint collection: https://www.kroll.com/en/services/cyber/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
- **Velociraptor** — endpoint hunting + DFIR collection: https://docs.velociraptor.app/
- **Volatility 3** — memory forensics framework: https://github.com/volatilityfoundation/volatility3
- **Sysinternals Suite** — Process Explorer, Autoruns, TCPView, Procmon: https://learn.microsoft.com/en-us/sysinternals/
- **Sigma → SIEM converter** (`sigma-cli`) — port the rules in `detections/sigma/` to your backend: https://github.com/SigmaHQ/sigma-cli

## Log Analysis & Timeline

Windows DFIR lives and dies by timeline quality. These tools turn raw artifacts into sorted, searchable event sequences.

- **Eric Zimmerman's Tools** — MFTECmd, PECmd, RECmd, EvtxECmd, Timeline Explorer; the gold standard for Windows artifact parsing: https://ericzimmerman.github.io/
- **Hayabusa** — fast Windows event-log threat hunting and SIGMA-based timeline generation: https://github.com/Yamato-Security/hayabusa
- **Chainsaw** — rapid Windows event-log triage with built-in SIGMA/built-in detection rules: https://github.com/WithSecureLabs/chainsaw
- **Plaso / log2timeline** — multi-source super-timeline builder (Windows, macOS, Linux artifacts): https://github.com/log2timeline/plaso
- **RITA (Real Intelligence Threat Analytics)** — detects C2 beacons and long-connection patterns in Zeek/Bro logs: https://github.com/activecm/rita
- **Zeek** — network security monitoring framework; produces structured protocol logs consumed by RITA and SIEMs: https://zeek.org/

## Threat Intel Feeds & Lookups

- **AbuseIPDB** — IP reputation: https://www.abuseipdb.com/
- **AlienVault OTX** — community IOC feed: https://otx.alienvault.com/
- **MalwareBazaar** — recent malware samples (hashes / YARA): https://bazaar.abuse.ch/
- **ThreatFox (abuse.ch)** — fresh IOCs by family: https://threatfox.abuse.ch/
- **URLhaus** — active malware URLs: https://urlhaus.abuse.ch/
- **PhishTank** — confirmed phishing URLs: https://phishtank.org/

## Purple Team & Adversary Emulation

- **Atomic Red Team** — small, scoped tests for ATT&CK techniques: https://github.com/redcanaryco/atomic-red-team
- **Caldera (MITRE)** — autonomous adversary emulation: https://github.com/mitre/caldera
- **PurpleSharp** — Windows adversary-simulation tool: https://github.com/mvelazc0/PurpleSharp
- **Stratus Red Team** — cloud-native attack emulation (AWS / Azure / GCP): https://github.com/DataDog/stratus-red-team

## Framework Helpers

- **MITRE ATT&CK**: https://attack.mitre.org/
- **ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/
- **NIST CSF 2.0**: https://www.nist.gov/cyberframework
- **CIS Critical Security Controls v8.1**: https://www.cisecurity.org/controls
- **Sigma rule reference**: https://github.com/SigmaHQ/sigma
