# TODO

Working backlog for daily updates. Grab the top item in whichever lane matches the day, write it, PR it, check it off.

Suggested cadence:

- **Mon — CVE:** pick one fresh CISA KEV addition and write it up using `vulnerabilities/template.md`.
- **Tue — Detection:** add one KQL or Sigma rule using a `detections/.../_template.*`.
- **Wed — Playbook:** publish one playbook from the list below or expand an existing one.
- **Thu — Threat intel:** add an actor profile, campaign, or TTP roundup.
- **Fri — Tools / frameworks:** review a tool or deepen a framework page.
- **Weekend:** cleanup, link-check, update `CHANGELOG.md`.

---

## Playbooks (priority order)

- [x] Phishing email triage — [`blue-team-playbooks/phishing-email-triage.md`](blue-team-playbooks/phishing-email-triage.md)
- [ ] Ransomware outbreak
- [ ] Business email compromise (BEC)
- [ ] Credential theft / password spray
- [ ] Lateral movement (RDP / SMB / WMI)
- [ ] Data exfiltration
- [ ] Insider threat
- [ ] Malware infection (endpoint)
- [ ] Cloud account compromise (Entra ID / AWS / GCP)
- [ ] DDoS

## Detection workflows

- [ ] Phishing email triage
- [ ] Suspicious sign-in (impossible travel / risky IP)
- [ ] Beaconing / C2 traffic
- [ ] LOLBin abuse (rundll32, mshta, regsvr32)
- [ ] Suspicious scheduled task / service install
- [ ] Office macro execution

## Detections (KQL / Sigma)

- [ ] T1078.004 — Entra ID risky sign-in followed by mailbox rule creation
- [ ] T1071.001 — beacon-like outbound HTTPS to rare destination
- [x] T1110.003 — password spray against Entra ID / AD — [KQL](detections/kql/T1110.003_entra-password-spray.md) · [Sigma](detections/sigma/T1110.003_entra-password-spray.md)
- [x] T1486 — mass file rename (ransomware canary) — [KQL](detections/kql/T1486_mass-file-rename-ransomware.md) · [Sigma](detections/sigma/T1486_mass-file-rename-ransomware.md)
- [ ] T1218.011 — rundll32 with unusual command line
- [ ] T1547.001 — new Run / RunOnce key written by non-installer
- [ ] T1021.001 — RDP from unusual source
- [x] T1003.001 — LSASS access by non-system process — [KQL](detections/kql/T1003.001_lsass-access-suspicious.md) · [Sigma](detections/sigma/T1003.001_lsass-access-suspicious.md)
- [x] Port the four existing KQL detections to Sigma — `detections/sigma/` (T1059.001, T1003.001, T1110.003, T1486)

## CVEs to write up

- [ ] Pick from current [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [ ] Backfill any CVE referenced in playbooks / detections

## Purple-team labs

- [ ] T1059.001 — Atomic Red Team encoded PowerShell tests vs. the KQL rule
- [ ] T1078 — valid accounts (Entra ID)
- [ ] T1021.001 — RDP lateral movement
- [ ] T1055 — process injection
- [ ] T1547.001 — run key persistence

## Threat intel

- [x] First actor profile — [Scattered Spider](threat-intelligence/actors/scattered-spider.md)
- [ ] First campaign write-up
- [ ] First TTP roundup (candidates: AiTM phishing kits, OAuth consent phishing, AS-REP roasting, MFA fatigue)

## Repo hygiene

- [x] Add a top-level `LICENSE` file (MIT)
- [x] Add issue templates (`new-cve`, `new-detection`, `new-playbook`, `tuning-request`)
- [x] Add PR template
- [x] Add `SECURITY.md`
- [x] Add `CODEOWNERS`
- [x] Add `.github/dependabot.yml`
- [x] Add MITRE ATT&CK `COVERAGE.md`
- [ ] Add badges to the root README once CI is green
- [ ] Add `CODE_OF_CONDUCT.md`
- [ ] Add Sigma syntax check + YARA syntax check to CI — [x] Sigma (`sigma-validate` job via pysigma); [ ] YARA
- [ ] Add spell check (typos) to CI
- [x] Add `detections/DATA_SOURCES.md` mapping rules → required telemetry — [`detections/DATA_SOURCES.md`](detections/DATA_SOURCES.md)
- [ ] Add per-backend "how to deploy" guides (Sentinel analytic rule, Defender custom detection, Splunk savedsearches.conf)
