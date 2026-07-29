# SentinelGo

**Insider Threat Detection & System Hardening Platform**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-46%20passing-brightgreen)](.)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue)](.)

---

## Overview

SentinelGo is a Go-based cybersecurity platform that detects potential insider threats, assesses system security posture, calculates risk scores, maps findings to MITRE ATT&CK, and provides actionable hardening recommendations.

Version 1.0 focuses on **deterministic rule-based detection** with a clear roadmap toward AI-assisted behavioural analytics.

```
Security Logs -> Collection -> Parsing -> Detection -> Risk Scoring -> MITRE Mapping -> Reports
```

---

## Features

### Insider Threat Detection
- **8 detection rules** covering brute force, privilege escalation, lateral movement, account enumeration, and more
- **YAML-based rule engine** — add custom rules without recompiling
- **MITRE ATT&CK mapping** for every detection (T1110, T1548, T1078, T1021, etc.)

### Risk Scoring
- Weighted scoring algorithm (severity x confidence x frequency x context)
- Per-finding and aggregate risk scores
- Configurable weights and thresholds

### System Hardening
- CIS-benchmark-aligned security checks
- Platform-adaptive (Windows + Linux)
- Actionable remediation recommendations

### Professional Reporting
- **HTML** — styled dark-theme executive reports
- **JSON** — machine-readable for integration
- Evidence-backed findings with recommendations

### Performance
- 10,000 events analyzed in < 300ms
- Minimal memory footprint
- Single binary, zero runtime dependencies

---

## Quick Start

```bash
# Build
go build -o sentinelgo ./cmd/sentinelgo/

# Analyze security logs
./sentinelgo analyze /var/log/auth.log

# Run hardening assessment
./sentinelgo harden

# List detection rules
./sentinelgo rules list

# Validate configuration
./sentinelgo validate
```

---

## Installation

### From Source

```bash
git clone https://github.com/sentinelgo/sentinelgo-ueba.git
cd sentinelgo-ueba
go mod tidy
go build -o sentinelgo ./cmd/sentinelgo/
```

### Pre-built Binaries

Download from the [Releases](https://github.com/sentinelgo/sentinelgo-ueba/releases) page.

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Windows  | amd64       | `sentinelgo-windows-amd64.exe` |
| Linux    | amd64       | `sentinelgo-linux-amd64` |
| macOS    | amd64       | `sentinelgo-darwin-amd64` |

---

## Usage

### Analyze Security Logs

```bash
# Analyze a specific log file
sentinelgo analyze /var/log/auth.log

# Analyze with custom config
sentinelgo analyze --config custom.yaml /path/to/logs

# Skip hardening assessment
sentinelgo analyze --skip-hardening /var/log/auth.log

# Scan (alias for analyze)
sentinelgo scan /var/log/auth.log
```

### System Hardening Assessment

```bash
sentinelgo harden
```

### Rule Management

```bash
# List all loaded rules
sentinelgo rules list

# Validate rule files
sentinelgo rules validate
```

### Configuration

```bash
# Validate configuration
sentinelgo validate

# Use custom config file
sentinelgo --config /path/to/config.yaml analyze logs/
```

---

## Architecture

```
+----------------------------------------------------------+
|                     CLI (Cobra)                           |
+----------------------------------------------------------+
|                   Engine Controller                       |
+------------+------------+------------+-------------------+
| Collector  |   Parser   |  Detection |    Hardening      |
|            |            |   Engine   |                   |
+------------+------------+------------+-------------------+
|            |            |   Scoring  |    Reporting      |
|            |            |   Engine   |  (JSON + HTML)    |
+------------+------------+------------+-------------------+
|              Config  |  Logger  |  Models                |
+----------------------------------------------------------+
```

### Pipeline

```
Input Logs
    |
    v
+---------+     +--------+     +-----------+     +---------+
|Collector|---->| Parser |---->| Detection |---->| Scoring |
+---------+     +--------+     +-----------+     +---------+
                                                       |
                                                       v
                                                 +-----------+
                                                 | Reporting |
                                                 +-----------+
```

---

## Detection Rules

| Rule | MITRE | Description |
|------|-------|-------------|
| DET-001 | T1110 | Brute Force Authentication |
| DET-002 | T1548 | Privilege Escalation |
| DET-003 | T1078 | Invalid User Enumeration |
| DET-004 | T1078 | After-Hours Authentication |
| DET-005 | T1110.004 | Account Enumeration / Credential Stuffing |
| DET-006 | T1110.001 | Rapid-Fire Authentication (Automated) |
| DET-007 | T1021 | Lateral Movement |
| DET-008 | T1078.001 | Service Account Interactive Login |

### Custom Rules

Add YAML files to the `rules/` directory:

```yaml
id: "CUSTOM-001"
name: "My Custom Rule"
description: "Detects specific insider threat pattern."
enabled: true
severity: "high"
confidence: 0.85
mitre:
  technique: "T1110"
  tactic: "Credential Access"
conditions:
  event_category: "authentication"
  event_outcome: "failure"
  group_by: "user"
  threshold: 10
  window_minutes: 5
recommendations:
  - "Investigate the account immediately."
```

---

## Configuration

See [`configs/sentinelgo.yaml`](configs/sentinelgo.yaml) for the complete configuration reference.

Key settings:

```yaml
logging:
  level: "info"        # debug, info, warn, error
  output: "console"    # console, file, both

detection:
  rules_path: "rules/"
  severity_threshold: "low"

scoring:
  weights:
    severity: 0.4
    confidence: 0.3
    frequency: 0.2
    context: 0.1

reporting:
  output_dir: "reports/"
  formats: ["json", "html"]
```

---

## Project Structure

```
sentinelgo-ueba/
├── cmd/sentinelgo/          # Application entry point
├── internal/
│   ├── collector/           # Log collection
│   ├── config/              # Configuration management
│   ├── detection/           # Rule engine + dynamic rules
│   ├── errors/              # Structured error types
│   ├── hardening/           # CIS benchmark checks
│   ├── logger/              # Structured logging (zap)
│   ├── models/              # Data models
│   ├── parser/              # Log parsing (syslog, Windows)
│   ├── reporting/           # Report generation (JSON, HTML)
│   └── scoring/             # Risk scoring engine
├── configs/                 # Default configuration
├── rules/                   # YAML detection rules
├── testdata/                # Sample log files
├── tests/                   # Integration tests & benchmarks
├── scripts/                 # Build & utility scripts
├── docs/                    # Documentation
├── Makefile                 # Build automation
└── go.mod
```

---

## Performance

Benchmarked on Ryzen 5 5600H (12 threads):

| Operation | 1,000 events | 10,000 events |
|-----------|-------------|---------------|
| Collection | 0.3ms | 1.6ms |
| Parsing | 22ms | 256ms |
| Detection (8 rules) | 0.8ms | 11ms |
| Scoring | 0.002ms | - |
| Full Pipeline | 29ms | 264ms |

---

## Development

```bash
# Download dependencies
make deps

# Run tests
make test

# Run benchmarks
make bench

# Generate coverage report
make coverage

# Format code
make fmt

# Build for current platform
make build

# Cross-platform release
make release

# Generate test data
make generate-testdata
```

---

## Roadmap

### Version 1.0 (Current)
- [x] Rule-based detection engine
- [x] YAML configurable rules
- [x] MITRE ATT&CK mapping
- [x] Risk scoring
- [x] CIS hardening assessment
- [x] HTML + JSON reporting
- [x] Cross-platform support

### Version 2.0 (Planned)
- [ ] Behavioural analytics (UEBA)
- [ ] Machine learning anomaly detection
- [ ] Plugin architecture
- [ ] REST API
- [ ] Real-time log streaming

### Version 3.0 (Future)
- [ ] Distributed agents
- [ ] Central management console
- [ ] SOAR integration
- [ ] Cloud deployment
- [ ] Web dashboard

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) — Threat framework
- [CIS Benchmarks](https://www.cisecurity.org/) — Hardening standards
- [Cobra](https://github.com/spf13/cobra) — CLI framework
- [Zap](https://github.com/uber-go/zap) — Structured logging
