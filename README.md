# NextLayerSec Guides

Comprehensive blue-team playbooks, detection workflows, purple-team lab guidance, and threat intelligence documentation designed for SOC teams, cybersecurity professionals, and students.  

> “The best defense is a well-informed offense and a prepared response.” — Blackvectra  

---

## 📚 Table of Contents
- [Overview](#overview)
- [Contents](#contents)
- [Usage](#usage)
- [Getting Started](#getting-started)
- [Contributing](#contributing)

---

## Overview
This repository provides structured, practical resources to support defensive security operations and collaborative red–blue team exercises. Whether you are an analyst, incident responder, or learner, you’ll find guides to improve detection capabilities, incident handling, and threat understanding.

---

## Contents
- **Frameworks** — Plain-English breakdowns + how to use:
  - [NIST CSF](frameworks/nist-csf.md)
  - [MITRE ATT&CK](frameworks/mitre-attack.md)
  - [ISO 27001](frameworks/iso-27001.md)
  - [IRS Publication 1075](frameworks/irs-pub-1075.md)
  - [SOC 2](frameworks/soc2.md)
- **[Blue Team Playbooks](blue-team-playbooks/)** — Incident response procedures (scenario index + template).
- **[Detection Workflows](detection-workflows/)** — Investigation checklists and triage flows.
- **[Detections](detections/)** — Reusable rule content:
  - [KQL](detections/kql/) (Sentinel / Defender XDR / Log Analytics)
  - [Sigma](detections/sigma/) (vendor-neutral)
  - [Splunk](detections/splunk/) (SPL)
  - [YARA](detections/yara/)
- **[Vulnerabilities](vulnerabilities/)** — Curated CVE write-ups (CISA KEV focus).
- **[Purple Team Labs](purple-team-labs/)** — Adversary emulation paired with the detections that should fire.
- **[Threat Intelligence](threat-intelligence/)** — Actor profiles, campaigns, and TTP roundups.
- **Tools** — Curated tools you’ll actually use:
  - [Blue Team & IR Tools](tools/blue-team-tools.md)
- **Templates** — Copy-and-use docs:
  - [Incident Report Template](incident-reports/template.md)
  - [CVE → Framework Mapping Template](vulnerabilities/template.md)

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for structure, templates, and CI checks. Open backlog in [TODO.md](TODO.md). Notable changes tracked in [CHANGELOG.md](CHANGELOG.md). MITRE ATT&CK coverage map: [COVERAGE.md](COVERAGE.md). Scheduled reminder/draft automation: [.github/AUTOMATION.md](.github/AUTOMATION.md). Security policy: [SECURITY.md](SECURITY.md). Licensed under [MIT](LICENSE).

---

## Usage
1. Browse **Frameworks** for quick context and practical “how to use” guidance.  
2. Use **Templates** to document incidents and CVE remediation with framework mapping.  
3. Leverage **Tools** for day-to-day security tasks.  
4. Customize any guide to match your environment or learning goals.  
5. Contributions (PRs) are welcome.  

> Use these guides as checklists in your SOC, or as structured practice in your lab.

---

## Getting Started
```bash
git clone https://github.com/Blackvectra/nextlayersec-guides.git
cd nextlayersec-guides
