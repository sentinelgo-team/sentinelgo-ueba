# SentinelGo

<div align="center">

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │    ░██████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      │
  │    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      │
  │    ╚█████╗ █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      │
  │     ╚═══██╗██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      │
  │    ██████╔╝███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗  │
  │    ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝  │
  │                                                                      │
  │                  G o  ·  S e c u r i t y  ·  P l a t f o r m       │
  │                                                                      │
  └──────────────────────────────────────────────────────────────────────┘
```

**Insider Threat Detection · Risk Scoring · System Hardening · MITRE ATT&CK**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-46%20passing-22c55e?style=flat-square)](tests/)
[![Version](https://img.shields.io/badge/Version-1.0.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-0ea5e9?style=flat-square)](.)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-8%20techniques-ef4444?style=flat-square)](https://attack.mitre.org/)

[Features](#features) · [Quick Start](#quick-start) · [Installation](#installation) · [Detection Rules](#detection-rules) · [Architecture](#architecture) · [Performance](#performance) · [Roadmap](#roadmap) · [Docs](docs/CLI.md)

</div>

---

## What is SentinelGo?

SentinelGo is a **Go-based cybersecurity platform** that ingests raw security logs, detects insider threat patterns, assesses system hardening posture, calculates risk scores, and generates professional HTML and JSON reports — delivered as a single binary with zero runtime dependencies.

> Version 1.0 is built on **deterministic rule-based detection**. The architecture is explicitly designed to support AI-assisted behavioural analytics in future releases.

---

## Features

<table>
<tr>
<td width="50%">

**Threat Detection**
- 8 built-in detection rules
- YAML rule engine — add rules without recompiling
- MITRE ATT&CK technique mapping on every finding
- Time-window clustering, threshold logic, user grouping

</td>
<td width="50%">

**Risk Scoring**
- Weighted algorithm: severity × confidence × frequency × context
- Per-finding scores + aggregate overall risk (0–100)
- Configurable weights via YAML
- Severity tiers: Critical / High / Medium / Low

</td>
</tr>
<tr>
<td width="50%">

**System Hardening**
- CIS Benchmark-aligned security checks
- Platform-adaptive: Windows and Linux
- Firewall, audit policy, password policy, SSH checks
- Remediation commands for every failed item

</td>
<td width="50%">

**Professional Reporting**
- Dark-theme HTML executive report
- Machine-readable JSON output
- Evidence-backed findings per detection
- MITRE tactic and technique per finding

</td>
</tr>
<tr>
<td width="50%">

**Multi-Format Log Parsing**
- Linux syslog (`auth.log`, `messages`)
- Windows Event Log key-value format
- Windows EVTX XML format
- 16 Windows Event IDs mapped to categories

</td>
<td width="50%">

**Performance**
- 10,000 events analyzed in **< 300 ms**
- Single binary, zero runtime dependencies
- Cross-platform: Windows / Linux / macOS
- Benchmarked collection, parsing, detection, scoring

</td>
</tr>
</table>

---

## Quick Start

```bash
# Build
go build -o sentinelgo ./cmd/sentinelgo/

# Analyze a log file (full pipeline)
./sentinelgo analyze testdata/auth.log

# Standalone hardening assessment
./sentinelgo harden

# List all loaded detection rules
./sentinelgo rules list
```

Reports are written to `reports/` as `scan-<id>.html` and `scan-<id>.json`.

---

## Installation

### From Source

```bash
git clone https://github.com/sentinelgo-team/sentinelgo-ueba.git
cd sentinelgo-ueba
go mod tidy
go build -o sentinelgo ./cmd/sentinelgo/
```

### Pre-built Binaries

Download from the [Releases](https://github.com/sentinelgo-team/sentinelgo-ueba/releases) page.

| Platform | Architecture | Binary |
|:--------:|:------------:|:------|
| Windows  | amd64 | `sentinelgo-windows-amd64.exe` |
| Linux    | amd64 | `sentinelgo-linux-amd64` |
| macOS    | amd64 | `sentinelgo-darwin-amd64` |

### Using Make

```bash
make build      # build for current platform  →  build/sentinelgo
make release    # build all three platforms   →  dist/
make install    # install to $GOPATH/bin
```

---

## CLI Commands

| Command | Description |
|:--------|:------------|
| `sentinelgo analyze [file]` | Full 5-phase pipeline: collect → parse → detect → score → report |
| `sentinelgo scan [file]` | Alias for `analyze` |
| `sentinelgo harden` | Standalone CIS hardening assessment |
| `sentinelgo rules list` | List all loaded detection rules |
| `sentinelgo rules validate` | Validate YAML rule files |
| `sentinelgo validate` | Validate configuration file |
| `sentinelgo version` | Show version, commit, platform |

**Global flag:** `--config / -c <path>` — custom config file (default: `configs/sentinelgo.yaml`)  
**Analyze flag:** `--skip-hardening` — skip CIS checks

Full reference: [docs/CLI.md](docs/CLI.md)

---

## Detection Rules

| ID | Technique | Tactic | Rule | Severity |
|:--:|:---------:|:------:|:-----|:--------:|
| DET-001 | T1110 | Credential Access | Brute Force Authentication | High |
| DET-002 | T1548 | Privilege Escalation | Privilege Escalation via sudo | High |
| DET-003 | T1078 | Initial Access | Invalid User Enumeration | Medium |
| DET-004 | T1078 | Initial Access | After-Hours Authentication | Medium |
| DET-005 | T1110.004 | Credential Access | Account Enumeration / Credential Stuffing | High |
| DET-006 | T1110.001 | Credential Access | Rapid-Fire Authentication (Automated) | Critical |
| DET-007 | T1021 | Lateral Movement | Multi-Host Authentication Pattern | High |
| DET-008 | T1078.001 | Persistence | Service Account Interactive Login | High |

### Custom Rules

Drop a `.yaml` file in `rules/` — no restart or recompile needed:

```yaml
id: "CUSTOM-001"
name: "Off-Hours Database Access"
description: "Database account used outside maintenance window."
enabled: true
severity: "high"
confidence: 0.85
mitre:
  technique: "T1078"
  tactic: "Initial Access"
conditions:
  event_category: "authentication"
  event_outcome: "success"
  user_list: ["postgres", "mysql", "mongodb"]
  time_constraint:
    after_hour: 23
    before_hour: 5
recommendations:
  - "Verify whether scheduled maintenance was planned."
  - "Review queries executed during this session."
  - "Rotate credentials if access was unauthorized."
```

Validate: `sentinelgo rules validate`

---

## Architecture

### System Overview

```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                    S e n t i n e l G o                              ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║                                                                      ║
  ║   CLI  (Cobra)                                                       ║
  ║   ├── analyze / scan    full 5-phase pipeline                        ║
  ║   ├── harden            standalone CIS assessment                   ║
  ║   ├── rules list        show loaded rules                           ║
  ║   ├── rules validate    check rule YAML files                       ║
  ║   ├── validate          check config file                           ║
  ║   └── version           build metadata                              ║
  ║                                                                      ║
  ╠═══════════════╦═══════════════╦══════════════════╦═══════════════════╣
  ║               ║               ║                  ║                   ║
  ║  Collector    ║  Parser       ║  Detection       ║  Hardening        ║
  ║  ───────────  ║  ───────────  ║  ─────────────   ║  ─────────────   ║
  ║  syslog       ║  syslog       ║  8 built-in      ║  CIS-WIN-001      ║
  ║  windows kv   ║  windows kv   ║  YAML dynamic    ║  CIS-WIN-004      ║
  ║  windows xml  ║  windows xml  ║  MITRE mapped    ║  CIS-LNX-002      ║
  ║               ║               ║                  ║  CIS-LNX-003      ║
  ╠═══════════════╩═══════════════╬══════════════════╩═══════════════════╣
  ║                               ║                                      ║
  ║  Scoring Engine               ║  Reporter                            ║
  ║  ────────────────────────     ║  ──────────────────────────────      ║
  ║  severity   × 0.40            ║  reports/scan-<id>.json              ║
  ║  confidence × 0.30            ║  reports/scan-<id>.html              ║
  ║  frequency  × 0.20            ║  dark-theme executive dashboard      ║
  ║  context    × 0.10            ║                                      ║
  ╠═══════════════════════════════╩══════════════════════════════════════╣
  ║  Foundation:  Config  ·  Logger (zap)  ·  Models  ·  Errors          ║
  ╚══════════════════════════════════════════════════════════════════════╝
```

### Analysis Pipeline

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  INPUT   ·   syslog  /  windows event log  /  windows xml        │
  └─────────────────────────────┬────────────────────────────────────┘
                                │
           ┌─────────────────── ▼ ───────────────────┐
    1 ─ 5  │  COLLECT                                 │
           │  FileCollector reads file, detects format│
           │  output → []RawEvent{ line, format }     │
           └─────────────────────┬───────────────────┘
                                 │
           ┌─────────────────── ▼ ───────────────────┐
    2 ─ 5  │  PARSE                                   │
           │  Normalize each line to structured Event │
           │  output → []Event{ user, host, category, │
           │                    action, outcome, meta }│
           └─────────────────────┬───────────────────┘
                                 │
           ┌─────────────────── ▼ ───────────────────┐
    3 ─ 5  │  DETECT                                  │
           │  8 rules × event set → []Finding         │
           │  each Finding: MITRE · evidence · recs   │
           └─────────────────────┬───────────────────┘
                                 │
           ┌─────────────────── ▼ ───────────────────┐
    4 ─ 5  │  SCORE                                   │
           │  weighted formula per finding (0–100)    │
           │  OverallRisk = max×0.6 + avg×0.4         │
           └─────────────────────┬───────────────────┘
                                 │
           ┌─────────────────── ▼ ───────────────────┐
    5 ─ 5  │  HARDEN  (optional, --skip-hardening)    │
           │  CIS checks → []HardeningFinding         │
           │  compliance = passed / total × 100       │
           └─────────────────────┬───────────────────┘
                                 │
  ┌──────────────────────────────▼───────────────────────────────────┐
  │  OUTPUT  ·  reports/scan-<id>.json   +   scan-<id>.html          │
  └──────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
  ┌──────────────┐    ┌──────────────────────┐    ┌──────────────────────────┐
  │  Raw Line    │    │  RawEvent            │    │  Event                   │
  │─────────────-│    │──────────────────────│    │──────────────────────────│
  │ "Jul 28      │ ──▶│ line:   "Jul 28 …"   │ ──▶│ category:  authentication│
  │  08:23:01    │    │ source: auth.log      │    │ action:    login         │
  │  sshd: Failed│    │ format: syslog        │    │ outcome:   failure       │
  │  password    │    │ linenum: 1            │    │ user:      admin         │
  │  for admin…" │    │                      │    │ host:      webserver      │
  └──────────────┘    └──────────────────────┘    │ timestamp: 2025-07-28    │
                                                  │ metadata:  reason=invalid│
                                                  └──────────────────────────┘

  ┌──────────────┐    ┌──────────────────────┐    ┌──────────────────────────┐
  │  []Event     │    │  Finding             │    │  ScanResult              │
  │─────────────-│    │──────────────────────│    │──────────────────────────│
  │ 22 events    │ ──▶│ rule_id:  DET-001    │ ──▶│ scan_id:   scan-1785317  │
  │ from         │    │ mitre:    T1110       │    │ risk_score: 72.9         │
  │ auth.log     │    │ severity: high        │    │ findings:  6             │
  │              │    │ score:    78.4        │    │ critical:  0             │
  │              │    │ evidence: [6 events]  │    │ high:      3             │
  │              │    │ recs:     [4 items]   │    │ medium:    3             │
  └──────────────┘    └──────────────────────┘    └──────────────────────────┘
```

---

## Project Structure

```
sentinelgo-ueba/
│
├── cmd/
│   └── sentinelgo/
│       └── main.go                   CLI entry point — 7 commands
│
├── internal/
│   ├── collector/
│   │   └── collector.go              file reader, format auto-detection
│   │
│   ├── config/
│   │   ├── config.go                 YAML loader, validation, env expansion
│   │   └── config_test.go            4 tests
│   │
│   ├── detection/
│   │   ├── engine.go                 rule registry, built-in + dynamic loader
│   │   ├── rules.go                  8 built-in detection rules (Go)
│   │   ├── loader.go                 YAML rule file loader and validator
│   │   ├── dynamic.go                runtime evaluation engine for YAML rules
│   │   ├── engine_test.go            10 tests
│   │   └── loader_test.go            6 tests
│   │
│   ├── errors/
│   │   └── errors.go                 structured error types with Kind field
│   │
│   ├── hardening/
│   │   ├── hardening.go              CIS benchmark checks, Windows + Linux
│   │   └── hardening_test.go         3 tests
│   │
│   ├── logger/
│   │   └── logger.go                 zap structured logging, console + file
│   │
│   ├── models/
│   │   └── event.go                  Event · Finding · ScanResult · HardeningResult
│   │
│   ├── parser/
│   │   ├── parser.go                 syslog · windows kv · windows xml parsing
│   │   └── parser_test.go            12 tests
│   │
│   ├── reporting/
│   │   └── report.go                 JSON and dark-theme HTML report generation
│   │
│   └── scoring/
│       ├── scoring.go                weighted risk scoring engine
│       └── scoring_test.go           6 tests
│
├── configs/
│   └── sentinelgo.yaml               default configuration file
│
├── rules/                            YAML detection rules — edit without recompile
│   ├── brute_force.yaml              DET-001 · T1110  · Brute Force
│   ├── privilege_escalation.yaml     DET-002 · T1548  · Privilege Escalation
│   ├── invalid_user.yaml             DET-003 · T1078  · Invalid User Enum
│   ├── after_hours.yaml              DET-004 · T1078  · After-Hours Login
│   ├── account_enumeration.yaml      DET-005 · T1110.004 · Account Enumeration
│   ├── rapid_fire.yaml               DET-006 · T1110.001 · Rapid-Fire Auth
│   ├── lateral_movement.yaml         DET-007 · T1021  · Lateral Movement
│   └── service_account.yaml          DET-008 · T1078.001 · Service Account Abuse
│
├── testdata/
│   ├── auth.log                      Linux syslog sample — 22 events
│   ├── windows_security.log          Windows Event Log sample — 16 events
│   └── medium_auth.log               synthetic dataset — 1,000 events
│
├── tests/
│   ├── integration_test.go           full pipeline integration tests — 5 tests
│   └── benchmark_test.go             performance benchmarks — 8 benchmarks
│
├── scripts/
│   ├── build.bat                     Windows build script
│   └── generate_testdata.go          synthetic log generator (1K / 10K)
│
├── docs/
│   └── CLI.md                        full CLI command reference
│
├── Makefile                          20+ build, test, lint, release targets
├── CHANGELOG.md                      version history
├── CONTRIBUTING.md                   developer guide
├── SECURITY.md                       vulnerability reporting policy
├── LICENSE                           MIT
└── go.mod
```

---

## Configuration

```yaml
# configs/sentinelgo.yaml

application:
  name: "SentinelGo"
  version: "1.0.0"
  environment: "production"       # development | staging | production

logging:
  level: "info"                   # debug | info | warn | error
  output: "console"               # console | file | both
  file_path: "logs/sentinelgo.log"

detection:
  rules_path: "rules/"            # scanned recursively for *.yaml files
  enabled: true
  severity_threshold: "low"       # minimum severity to include in output

scoring:
  algorithm: "weighted"
  max_score: 100
  weights:                        # must sum to 1.0
    severity:   0.40
    confidence: 0.30
    frequency:  0.20
    context:    0.10

reporting:
  output_dir: "reports/"
  formats: ["json", "html"]
  include_evidence: true
  include_recommendations: true

hardening:
  enabled: true
  benchmarks: ["cis-windows-11"]
```

---

## Hardening Checks

| Check ID | Platform | Description | Severity |
|:--------:|:--------:|:------------|:--------:|
| CIS-WIN-001 | Windows | Firewall enabled — Domain profile | High |
| CIS-WIN-002 | Windows | Firewall enabled — Private profile | High |
| CIS-WIN-003 | Windows | Firewall enabled — Public profile | High |
| CIS-WIN-004 | Windows | Audit policy covers logon events | Medium |
| CIS-WIN-005 | Windows | Windows Update service running | Medium |
| CIS-WIN-006 | Windows | Password minimum length ≥ 14 | High |
| CIS-LNX-001 | Linux | `/etc/passwd` not world-writable | Critical |
| CIS-LNX-002 | Linux | SSH `PermitRootLogin` disabled | High |
| CIS-LNX-003 | Linux | Firewall (ufw / firewalld) active | High |
| CIS-LNX-004 | Linux | Password aging configured | Medium |

---

## Performance

Benchmarked on **AMD Ryzen 5 5600H** — Windows 11, 12 threads:

| Operation | 1,000 events | 10,000 events | Memory (10K) |
|:----------|:------------:|:-------------:|:------------:|
| Collection | 0.3 ms | 1.6 ms | 4.7 MB |
| Parsing | 22 ms | 256 ms | 248 MB |
| Detection — 8 rules | 0.8 ms | 11 ms | 32 MB |
| Scoring — 100 findings | < 0.002 ms | — | 0 B |
| **Full Pipeline** | **29 ms** | **264 ms** | **285 MB** |

```bash
make bench
# go test ./tests/ -bench=. -benchmem -run=^$
```

---

## Development

```bash
make deps               # download and tidy dependencies
make test               # run all 46 tests
make bench              # run 8 performance benchmarks
make coverage           # generate HTML coverage report → build/coverage.html
make fmt                # format all Go source files
make lint               # go vet + format check
make build              # build for current platform  →  build/sentinelgo
make release            # build Windows + Linux + macOS  →  dist/
make generate-testdata  # generate 1K and 10K synthetic log files
make clean              # remove build/ and dist/
```

### Adding a Detection Rule

```bash
# 1. Create the rule file
touch rules/myorg_custom.yaml

# 2. Edit it following the YAML schema (see Detection Rules section above)

# 3. Validate it
sentinelgo rules validate

# 4. Test it against sample data
sentinelgo analyze testdata/auth.log --skip-hardening

# No recompile or restart needed
```

---

## Roadmap

### v1.0 — Released

| Feature | Status |
|:--------|:------:|
| Rule-based detection engine | Done |
| YAML-configurable rules | Done |
| MITRE ATT&CK mapping | Done |
| Weighted risk scoring | Done |
| CIS hardening — Windows + Linux | Done |
| HTML + JSON reporting | Done |
| Multi-format log parsing | Done |
| Cross-platform builds | Done |
| 46 tests + 8 benchmarks | Done |

### v2.0 — Planned

| Feature | Description |
|:--------|:------------|
| UEBA Behavioural Analytics | Baseline per-user behaviour, flag statistical deviations |
| ML Anomaly Detection | Unsupervised anomaly scoring on event sequences |
| Plugin Architecture | Loadable `.so` / `.dll` rule plugins |
| REST API | HTTP server for programmatic log ingestion |
| Real-time Streaming | Tail log files, emit findings live |

### v3.0 — Future

| Feature | Description |
|:--------|:------------|
| Distributed Agents | Deploy collectors on remote hosts |
| Central Console | Web UI for fleet-wide threat visibility |
| SOAR Integration | Webhook / API push to XSOAR, Splunk SOAR |
| Cloud Packaging | Docker, Kubernetes, cloud-native deployment |

---

## License

Licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

| Project | Purpose |
|:--------|:--------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Threat classification framework |
| [CIS Benchmarks](https://www.cisecurity.org/) | System hardening standards |
| [Cobra](https://github.com/spf13/cobra) | CLI framework |
| [Zap](https://github.com/uber-go/zap) | Structured logging |
| [yaml.v3](https://github.com/go-yaml/yaml) | YAML parsing |

---

<div align="center">
<b>SentinelGo v1.0.0</b> &nbsp;·&nbsp; Go &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; MITRE ATT&CK Mapped
</div>
