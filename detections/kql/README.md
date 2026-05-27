# KQL Detections

Kusto Query Language (KQL) detections for Microsoft Sentinel, Defender XDR, and Log Analytics.

## File pairing

Each detection ships as two files with the same basename:

- `<name>.kql` — the query itself, runnable as-is
- `<name>.md` — context, data sources, ATT&CK mapping, FP notes, tuning

## Template

See [`_template.md`](_template.md) and [`_template.kql`](_template.kql).

## Index

| Technique | File | Status | Description |
|-----------|------|--------|-------------|
| T1059.001 | `_template` | example | Template — replace with real detections |
