# 🔒 Drift

**Continuous Architecture Drift Detection & Threat Modelling Engine**

> *"Keep threat models alive as architectures evolve."*

Drift is a CLI-first hybrid engine that combines **deterministic STRIDE analysis** with **AI-augmented reasoning** to detect architectural drift and produce threat deltas.

**Drift is NOT** a vulnerability scanner, pentesting tool, or deployment blocker.

**Drift IS** a continuous threat modeling engine that runs locally and in GitHub Actions.

---

## Philosophy

- **Deterministic where possible** — Rule-based STRIDE, risk scoring, boundary detection
- **AI where beneficial** — Explanations, prioritization, delta summaries
- **Explainable** — Every threat carries evidence, boundary context, and mitigation
- **Non-blocking** — Never blocks deployments; produces deltas, not gates
- **CI-native** — Runs in GitHub Actions; posts PR comments with threat deltas

---

## Quick Start

```bash
# Install
pip install -e .

# Analyze architecture
drift analyze ./examples

# Create baseline snapshot
drift baseline ./examples

# Detect drift (compare against baseline)
drift diff ./examples

# Generate report
drift report ./examples

# GitHub PR comment (in CI)
drift github ./examples
```

---

## Inputs

| Format | File | What Drift Extracts |
|--------|------|-------------------|
| Docker Compose | `docker-compose*.yml` | Services, ports, dependencies, env vars |
| Terraform | `*.tf` | Cloud resources, VPCs, security groups, IAM |
| Kubernetes | `*.yaml` (with `kind`) | Deployments, services, ingress, network policies |
| Manual Override | `architecture.json` | Explicit components, flows, boundaries |
| Baseline | `.drift/drift.lock` | Previous architecture snapshot |

---

## Features

### 1. Architecture Inference
Automatically builds an architecture graph from infrastructure files:
```
Browser → API Gateway → Auth Service → Database
                      → Payment Service → Database
                      → User Service → Cache
```

### 2. Trust Boundary Detection
Classifies components into trust zones and detects boundary crossings:
- Public Internet
- DMZ
- Internal Services
- Database Tier
- PCI Zone
- Third-Party APIs

### 3. STRIDE Threat Modeling
Deterministic, evidence-based threat generation for every boundary-crossing flow:
- **Spoofing** — Missing authentication
- **Tampering** — Unencrypted data in transit
- **Repudiation** — Missing audit trails
- **Information Disclosure** — Plaintext protocols, public databases
- **Denial of Service** — Public-facing services without rate limiting
- **Elevation of Privilege** — Overly permissive IAM, privileged containers

### 4. Risk Scoring
`Likelihood × Impact` matrix producing Critical / High / Medium / Low severity.

### 5. Threat Delta Engine ⭐
The core differentiator. Compares current state against `drift.lock`:
```
+ 3 new threats (1 critical, 2 high)
- 2 mitigated threats
+ 1 new component: legacy-service
+ 1 new boundary: DMZ → PCI Zone
```

### 6. AI Augmentation ⭐
AI explains what the rule engine finds — it does NOT generate threats:
```
Rule engine: "HTTP between API Gateway and Payment Service"

AI explains: "Sensitive payment data crosses from Internal Services to the
PCI Zone over plaintext HTTP, creating Information Disclosure and Tampering
risks. Enforce TLS 1.3 with mTLS between services."
```

### 7. GitHub PR Comments ⭐⭐⭐
```markdown
## 🔒 Drift Threat Delta

### New Threats
| Severity | Category | Title | Boundary |
|----------|----------|-------|----------|
| 🔴 HIGH | Information Disclosure | Payment traffic over HTTP | Internal → PCI |

### Mitigated
- ~~Missing CSP~~
```

---

## AI Configuration

Drift uses Google Gemini for AI augmentation. Set your API key:

```bash
export GEMINI_API_KEY=your-key-here
```

Without an API key, Drift works perfectly with rule-based analysis only. Use `--no-ai` to explicitly skip AI.

---

## GitHub Actions

```yaml
name: Drift Threat Modeling

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install drift-cli
      - run: drift analyze .
      - run: drift diff .
      - run: drift github .
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Architecture

```
drift/
├── main.py                       # Entry point
├── cli.py                        # Typer CLI commands
├── models.py                     # Pydantic data models
├── parser/                       # Input parsers
│   ├── compose_parser.py         # docker-compose.yml
│   ├── terraform_parser.py       # *.tf files
│   ├── k8s_parser.py             # K8s manifests
│   └── json_parser.py            # architecture.json
├── engine/                       # Analysis engines
│   ├── architecture_builder.py   # Build component graph
│   ├── rule_engine.py            # Deterministic STRIDE + risk
│   ├── drift_engine.py           # Threat delta comparison
│   └── ai_engine.py              # AI explanation layer
├── baseline/
│   └── baseline_manager.py       # drift.lock management
├── report/
│   ├── rich_output.py            # Terminal dashboard
│   └── markdown_report.py        # THREAT_REPORT.md
└── github/
    └── pr_comment.py             # PR comments
```

---

## License

MIT
