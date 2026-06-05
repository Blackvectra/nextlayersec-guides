# Sigma Detections

Vendor-neutral [Sigma](https://github.com/SigmaHQ/sigma) rules. Convert to your SIEM with `sigma convert -t <backend>`.

Each rule pairs `<name>.yml` with `<name>.md` notes. Use [`_template.yml`](_template.yml) as the starting point.

## Validation

CI validates every non-template rule with pySigma. Run the identical check locally before pushing:

```bash
pip install "pysigma>=1.3,<2"
python detections/sigma/validate_rules.py
```

## Index

| Technique | File | Status | Description |
|-----------|------|--------|-------------|
| T1003.001 | [`T1003.001_lsass-access-suspicious`](T1003.001_lsass-access-suspicious.md) | experimental | Non-Microsoft process opens LSASS with credential-dump-capable rights |
| T1566.001 | [`T1566.001_attachment-link-credential-harvester`](T1566.001_attachment-link-credential-harvester.md) | experimental | Delivered inbound attachment mail + harvester link on abused hosting (`temporal` correlation) |
| T1059.001 | [`T1059.001_powershell-encoded-command`](T1059.001_powershell-encoded-command.md) | experimental | PowerShell `-EncodedCommand` / `FromBase64String` |
| T1110.003 | [`T1110.003_entra-password-spray`](T1110.003_entra-password-spray.md) | experimental | Single IP fails sign-ins against many Entra users (`value_count` correlation) |
| T1486 | [`T1486_mass-file-rename-ransomware`](T1486_mass-file-rename-ransomware.md) | experimental | Process renames many files on one host — ransomware canary (`event_count` correlation) |
| T1547.001 | [`T1547.001_runkey-persistence`](T1547.001_runkey-persistence.md) | experimental | Non-installer process writes a Run / RunOnce / Winlogon autostart value |
| T1071.001 | [`T1071.001_beaconing-rare-https`](T1071.001_beaconing-rare-https.md) | experimental | Sustained HTTPS to a fleet-rare destination (`event_count` correlation; SIEM-side rarity check) |
