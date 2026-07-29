<div align="center">

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ██████╗  ██████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔════╝ ██╔═══██╗
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║  ███╗██║   ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║   ██║██║   ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗╚██████╔╝╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝
```

**Insider Threat Detection & System Hardening Platform**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-46%20passing-22c55e?style=flat&logo=checkmarx)](.)
[![Version](https://img.shields.io/badge/Version-1.0.0-6366f1?style=flat)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0ea5e9?style=flat)](.)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-ef4444?style=flat)](https://attack.mitre.org/)

[Features](#features) · [Quick Start](#quick-start) · [Installation](#installation) · [Detection Rules](#detection-rules) · [Architecture](#architecture) · [Performance](#performance) · [Roadmap](#roadmap)

</div>

---

## What is SentinelGo?

SentinelGo is a **Go-based cybersecurity platform** that ingests raw security logs, detects insider threat patterns, assesses system hardening posture, scores risk using a weighted algorithm, and generates professional HTML and JSON reports — all in a single binary with zero runtime dependencies.

> Version 1.0 is built on **deterministic rule-based detection**. The architecture is explicitly designed for AI-assisted behavioural analytics in future releases.

```
Raw Logs  ──►  Collect  ──►  Parse  ──►  Detect  ──►  Score  ──►  Harden  ──►  Report
               (syslog       (normalize   (8 rules,    (weighted    (CIS        (HTML +
                Windows       events)      MITRE        algorithm)   checks)     JSON)
                XML)                       mapped)
```

---

## Features

<table>
<tr>
<td width="50%">

### Threat Detection
- 8 built-in detection rules
- YAML rule engine — no recompile needed
- MITRE ATT&CK technique mapping
- Time-window clustering & threshold logic
- After-hours, lateral movement, service account abuse detection

</td>
<td width="50%">

### Risk Scoring
- Weighted algorithm: severity × confidence × frequency × context
- Per-finding and aggregate risk scores (0–100)
- Configurable weights via YAML
- Finding severity: Critical / High / Medium / Low

</td>
</tr>
<tr>
<td width="50%">

### System Hardening
- CIS Benchmark-aligned checks
- Platform-adaptive: Windows + Linux
- Firewall, audit policy, password policy, SSH config
- Remediation commands for every failed check

</td>
<td width="50%">

### Professional Reporting
- Dark-theme HTML executive report
- Machine-readable JSON output
- Evidence-backed findings
- MITRE technique references per finding

</td>
</tr>
<tr>
<td width="50%">

### Multi-Format Log Parsing
- Linux syslog (`auth.log`, `messages`)
- Windows Event Log (key-value)
- Windows EVTX (XML format)
- 16 Windows Event IDs mapped

</td>
<td width="50%">

### Performance
- 10,000 events analyzed in **< 300ms**
- Single binary, zero runtime dependencies
- Cross-platform: Windows / Linux / macOS
- Minimal memory footprint

</td>
</tr>
</table>

---

## Quick Start

```bash
# 1. Build
go build -o sentinelgo ./cmd/sentinelgo/

# 2. Analyze a log file
./sentinelgo analyze testdata/auth.log

# 3. Standalone hardening check
./sentinelgo harden

# 4. List loaded detection rules
./sentinelgo rules list
```

Reports are written to `reports/` as both `.html` and `.json`.

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
|:--------:|:------------:|:------:|
| Windows  | amd64 | `sentinelgo-windows-amd64.exe` |
| Linux    | amd64 | `sentinelgo-linux-amd64` |
| macOS    | amd64 | `sentinelgo-darwin-amd64` |

### Using Make

```bash
make build          # current platform
make release        # all three platforms at once
make install        # copy to $GOPATH/bin
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
| `sentinelgo version` | Show version, platform, build info |

**Flags:**

| Flag | Command | Description |
|:-----|:--------|:------------|
| `--skip-hardening` | analyze / scan | Skip CIS checks |
| `--config` / `-c` | all | Custom config file path |

---

## Detection Rules

| Rule ID | MITRE Technique | Tactic | Description | Severity |
|:-------:|:---------------:|:------:|:------------|:--------:|
| DET-001 | T1110 | Credential Access | Brute Force Authentication | High |
| DET-002 | T1548 | Privilege Escalation | Privilege Escalation via sudo | High |
| DET-003 | T1078 | Initial Access | Invalid User Enumeration | Medium |
| DET-004 | T1078 | Initial Access | After-Hours Authentication | Medium |
| DET-005 | T1110.004 | Credential Access | Account Enumeration / Credential Stuffing | High |
| DET-006 | T1110.001 | Credential Access | Rapid-Fire Authentication (Automated) | Critical |
| DET-007 | T1021 | Lateral Movement | Multi-Host Authentication Pattern | High |
| DET-008 | T1078.001 | Persistence | Service Account Interactive Login | High |

### Writing Custom Rules

Drop a YAML file into `rules/` — no restart or recompile needed:

```yaml
id: "CUSTOM-001"
name: "Off-Hours Database Access"
description: "Database service account used outside maintenance window."
enabled: true
severity: "high"
confidence: 0.85

mitre:
  technique: "T1078"
  tactic: "Initial Access"

conditions:
  event_category: "authentication"
  event_outcome: "success"
  user_list:
    - "postgres"
    - "mysql"
    - "mongodb"
  time_constraint:
    after_hour: 23
    before_hour: 5

recommendations:
  - "Verify whether scheduled maintenance was planned."
  - "Review all queries executed during this session."
  - "Rotate credentials if access was unauthorized."
```

Validate with: `sentinelgo rules validate`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLI  (Cobra)                                │
│          analyze · scan · harden · rules · validate · version        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
            ┌───────────────▼───────────────┐
            │       Engine Controller        │
            └──┬────────┬────────┬──────────┘
               │        │        │
    ┌──────────▼──┐ ┌───▼────┐ ┌─▼──────────┐ ┌─────────────┐
    │  Collector  │ │ Parser │ │  Detection  │ │  Hardening  │
    │             │ │        │ │   Engine    │ │   Engine    │
    │  syslog     │ │syslog  │ │             │ │             │
    │  win kv     │ │win kv  │ │  8 rules    │ │  CIS checks │
    │  win xml    │ │win xml │ │  + dynamic  │ │  Win+Linux  │
    └─────────────┘ └────────┘ └──────┬──────┘ └──────┬──────┘
                                      │               │
                            ┌─────────▼──────┐        │
                            │ Scoring Engine │        │
                            │                │        │
                            │ severity×0.4   │        │
                            │ confidence×0.3 │        │
                            │ frequency×0.2  │        │
                            │ context×0.1    │        │
                            └────────┬───────┘        │
                                     │                │
                            ┌────────▼────────────────▼──┐
                            │       Reporter              │
                            │   JSON report · HTML report │
                            └─────────────────────────────┘
```

### Analysis Pipeline

```
  ┌──────────┐
  │ Log File │
  └────┬─────┘
       │
  [1/5]│ Collect ──── FileCollector reads lines, detects format
       │
  [2/5]│ Parse ─────── Normalize to Event{category, action, user, host, outcome}
       │
  [3/5]│ Detect ────── 8 rules × all events → []Finding{MITRE, evidence, severity}
       │
  [4/5]│ Score ─────── Weighted risk score per finding → overall risk (0–100)
       │
  [5/5]│ Harden ────── CIS checks → []HardeningFinding{status, remediation}
       │
  ┌────▼──────────────────────┐
  │  reports/scan-<id>.json   │
  │  reports/scan-<id>.html   │
  └───────────────────────────┘
```

---

## Project Structure

```
sentinelgo-ueba/
│
├── cmd/
│   └── sentinelgo/
│       └── main.go                  ← CLI entry point (7 commands)
│
├── internal/
│   ├── collector/
│   │   └── collector.go             ← File collection, format auto-detection
│   ├── config/
│   │   ├── config.go                ← YAML load, validation, env expansion
│   │   └── config_test.go
│   ├── detection/
│   │   ├── engine.go                ← Rule registry (built-in + dynamic)
│   │   ├── rules.go                 ← 8 built-in detection rules
│   │   ├── loader.go                ← YAML rule file loader + validator
│   │   ├── dynamic.go               ← Runtime rule evaluation engine
│   │   ├── engine_test.go           ← 10 detection tests
│   │   └── loader_test.go           ← 6 loader tests
│   ├── errors/
│   │   └── errors.go                ← Structured error types
│   ├── hardening/
│   │   ├── hardening.go             ← CIS benchmark checks (Windows + Linux)
│   │   └── hardening_test.go
│   ├── logger/
│   │   └── logger.go                ← zap structured logging
│   ├── models/
│   │   └── event.go                 ← Event, Finding, ScanResult, HardeningResult
│   ├── parser/
│   │   ├── parser.go                ← Syslog, Windows KV, Windows XML parsing
│   │   └── parser_test.go           ← 12 parser tests
│   ├── reporting/
│   │   └── report.go                ← JSON + dark-theme HTML report generation
│   └── scoring/
│       ├── scoring.go               ← Weighted risk scoring engine
│       └── scoring_test.go          ← 6 scoring tests
│
├── configs/
│   └── sentinelgo.yaml              ← Default configuration
│
├── rules/                           ← YAML detection rules (editable, hot-loadable)
│   ├── brute_force.yaml             ← DET-001 · T1110
│   ├── privilege_escalation.yaml    ← DET-002 · T1548
│   ├── invalid_user.yaml            ← DET-003 · T1078
│   ├── after_hours.yaml             ← DET-004 · T1078
│   ├── account_enumeration.yaml     ← DET-005 · T1110.004
│   ├── rapid_fire.yaml              ← DET-006 · T1110.001
│   ├── lateral_movement.yaml        ← DET-007 · T1021
│   └── service_account.yaml         ← DET-008 · T1078.001
│
├── testdata/
│   ├── auth.log                     ← Linux syslog sample (22 events)
│   ├── windows_security.log         ← Windows Event Log sample (16 events)
│   └── medium_auth.log              ← Synthetic dataset (1,000 events)
│
├── tests/
│   ├── integration_test.go          ← Full pipeline integration tests (5 tests)
│   └── benchmark_test.go            ← Performance benchmarks (8 benchmarks)
│
├── scripts/
│   ├── build.bat                    ← Windows build script
│   └── generate_testdata.go         ← Synthetic log generator
│
├── docs/
│   └── CLI.md                       ← Full CLI command reference
│
├── Makefile                         ← 20+ build, test, lint, release targets
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE                          ← MIT
└── go.mod
```

---

## Configuration

```yaml
# configs/sentinelgo.yaml

application:
  name: "SentinelGo"
  version: "1.0.0"
  environment: "production"

logging:
  level: "info"           # debug | info | warn | error
  output: "console"       # console | file | both
  file_path: "logs/sentinelgo.log"

detection:
  rules_path: "rules/"    # directory scanned for *.yaml rule files
  enabled: true
  severity_threshold: "low"

scoring:
  algorithm: "weighted"
  max_score: 100
  weights:
    severity:   0.40      # weight must sum to 1.0
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

## Performance

Benchmarked on **AMD Ryzen 5 5600H** (12 threads, Windows 11):

| Operation | 1,000 events | 10,000 events | Memory (10K) |
|:----------|:------------:|:-------------:|:------------:|
| Collection | 0.3 ms | 1.6 ms | 4.7 MB |
| Parsing | 22 ms | 256 ms | 248 MB |
| Detection (8 rules) | 0.8 ms | 11 ms | 32 MB |
| Scoring (100 findings) | < 0.002 ms | — | 0 B |
| **Full Pipeline** | **29 ms** | **264 ms** | **285 MB** |

Run benchmarks yourself:

```bash
make bench
# or
go test ./tests/ -bench=. -benchmem -run=^$
```

---

## Development

```bash
make deps             # download & tidy dependencies
make test             # run all 46 tests
make bench            # run 8 performance benchmarks
make coverage         # generate HTML coverage report
make fmt              # format all Go source files
make lint             # run go vet + format check
make build            # build for current platform → build/sentinelgo
make release          # build for Windows + Linux + macOS → dist/
make generate-testdata  # generate 1K and 10K synthetic log files
make clean            # remove build/ and dist/
```

### Adding a Detection Rule

1. Create `rules/myorg_rule.yaml` following the schema above
2. Run `sentinelgo rules validate` to check it
3. Run `sentinelgo analyze testdata/auth.log --skip-hardening` to test it
4. No recompile needed — rules are loaded at runtime

---

## Hardening Checks

| Check ID | Platform | Title | Severity |
|:--------:|:--------:|:------|:--------:|
| CIS-WIN-001 | Windows | Firewall enabled (Domain profile) | High |
| CIS-WIN-002 | Windows | Firewall enabled (Private profile) | High |
| CIS-WIN-003 | Windows | Firewall enabled (Public profile) | High |
| CIS-WIN-004 | Windows | Audit policy covers logon events | Medium |
| CIS-WIN-005 | Windows | Windows Update service running | Medium |
| CIS-WIN-006 | Windows | Password minimum length ≥ 14 | High |
| CIS-LNX-001 | Linux | /etc/passwd world-writable check | Critical |
| CIS-LNX-002 | Linux | SSH PermitRootLogin disabled | High |
| CIS-LNX-003 | Linux | Firewall (ufw/firewalld) active | High |
| CIS-LNX-004 | Linux | Password aging configured | Medium |

---

## Roadmap

### v1.0 — Current Release

| Feature | Status |
|:--------|:------:|
| Rule-based detection engine | Done |
| YAML-configurable rules | Done |
| MITRE ATT&CK mapping | Done |
| Weighted risk scoring | Done |
| CIS hardening (Windows + Linux) | Done |
| HTML + JSON reporting | Done |
| Multi-format log parsing | Done |
| Cross-platform builds | Done |
| 46 tests + 8 benchmarks | Done |

### v2.0 — Planned

| Feature | Description |
|:--------|:------------|
| UEBA Behavioural Analytics | Baseline normal behaviour per user, flag deviations |
| ML Anomaly Detection | Unsupervised anomaly scoring on event sequences |
| Plugin Architecture | Loadable `.so`/`.dll` rule plugins |
| REST API | HTTP server for programmatic log submission |
| Real-time Streaming | Tail log files and emit findings live |

### v3.0 — Future

| Feature | Description |
|:--------|:------------|
| Distributed Agents | Deploy collectors on remote hosts |
| Central Console | Web UI for fleet-wide visibility |
| SOAR Integration | Webhook/API push to XSOAR, Splunk SOAR |
| Cloud Deployment | Docker, Kubernetes, cloud-native packaging |

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

| Project | Role |
|:--------|:-----|
| [MITRE ATT&CK](https://attack.mitre.org/) | Threat classification framework |
| [CIS Benchmarks](https://www.cisecurity.org/) | Hardening standards |
| [Cobra](https://github.com/spf13/cobra) | CLI framework |
| [Zap](https://github.com/uber-go/zap) | Structured logging |
| [yaml.v3](https://github.com/go-yaml/yaml) | YAML parsing |

---

<div align="center">

**SentinelGo v1.0.0** — Built in Go · MIT License · MITRE ATT&CK Mapped

</div>
