# Detections

Reusable detection content for SOC teams. Each rule pairs a query file with a markdown sibling that explains intent, data sources, ATT&CK mapping, false-positive notes, and tuning guidance.

## Layout

```
detections/
├── kql/        # Microsoft Sentinel / Defender XDR / Log Analytics
├── sigma/      # Vendor-neutral Sigma rules (YAML)
├── splunk/     # SPL searches
└── yara/       # YARA rules for file / memory matching
```

## Conventions

- **One detection per file.** Name files `T<technique>_short-description.<ext>` (e.g., `T1059.001_powershell-encoded-command.kql`).
- **Every rule gets a markdown sibling** with the same basename (e.g., `T1059.001_powershell-encoded-command.md`) using the template in each subfolder.
- **Tag with ATT&CK technique IDs** in the markdown sibling so detections are cross-referenceable with playbooks and CVE entries.
- **Link to upstream** when adapting from public rules (Sigma HQ, Elastic, Splunk ESCU, Microsoft samples).

## Status legend

Use these tags in the markdown sibling:

- `status: production` — tuned, low FP, deploy-ready
- `status: testing` — needs validation in your environment
- `status: experimental` — proof of concept, expect noise
