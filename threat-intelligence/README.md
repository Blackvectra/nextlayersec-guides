# Threat Intelligence

Short, opinionated notes on actors, campaigns, and TTPs that matter to the defenders this repo serves. Not a feed — a curated knowledge base.

## Layout

```
threat-intelligence/
├── actors/      # one file per actor / group (APT29, Scattered Spider, etc.)
├── campaigns/   # one file per named campaign / operation
└── ttps/        # roundups of techniques (e.g., "AS-REP roasting in the wild")
```

Use the templates in each subfolder.

## Index

### Actors

| Group | File | Status |
|-------|------|--------|
| Scattered Spider (UNC3944 / Octo Tempest / Muddled Libra) | [actors/scattered-spider.md](actors/scattered-spider.md) | published |

### Campaigns

| Campaign | File | Period | Actor | Status |
|----------|------|--------|-------|--------|
| Scattered Spider — 2023 Hospitality Sector Breaches | [campaigns/scattered-spider-casino-2023.md](campaigns/scattered-spider-casino-2023.md) | 2023-05 – 2023-12 | Scattered Spider / UNC3944 | published |

### TTPs

| Roundup | File | Status |
|---------|------|--------|
| Adversary-in-the-Middle (AiTM) phishing kits | [ttps/aitm-phishing-kits.md](ttps/aitm-phishing-kits.md) | published |
