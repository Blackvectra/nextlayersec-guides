# Purple Team Labs

Adversary emulation exercises paired with the detections that should fire. Each lab maps a known TTP (typically an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test) to the detection content in `detections/` and the playbook in `blue-team-playbooks/` that should handle the alert.

## Layout

Each lab is its own directory containing:

```
purple-team-labs/<lab-name>/
├── README.md          # what we emulate and what should fire
├── emulation.md       # exact commands / atomic test IDs
└── results.md         # what fired, what didn't, gaps identified
```

## Index

| Lab | Technique | Status |
|-----|-----------|--------|
| _todo_ | T1059.001 PowerShell encoded command | planned |
| _todo_ | T1078 valid accounts (Entra ID) | planned |
| _todo_ | T1021.001 RDP lateral movement | planned |
| _todo_ | T1055 process injection | planned |
| _todo_ | T1547.001 run key persistence | planned |

Use [`_template/`](_template/) as the starting point.
