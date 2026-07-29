# Changelog

All notable changes to SentinelGo are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2025-07-29

### Added

#### Core Platform
- Go-based CLI application with Cobra framework
- YAML configuration with validation and environment variable support
- Structured logging via zap (console + file, level-filtered)
- Modular architecture with clean separation of concerns

#### Detection Engine
- 8 built-in detection rules
- YAML-based external rule definitions (editable without recompilation)
- Dynamic rule evaluation engine supporting:
  - Threshold-based detection
  - Time-window clustering
  - Group-by-user analysis
  - Group-by-source analysis
  - Distinct-host counting (lateral movement)
  - Distinct-target counting (account enumeration)
  - Time-of-day constraints (after-hours)
  - User-list matching (service accounts)
  - Metadata filtering

#### Detection Rules
- DET-001: Brute Force Authentication (T1110)
- DET-002: Privilege Escalation (T1548)
- DET-003: Invalid User Enumeration (T1078)
- DET-004: After-Hours Authentication (T1078)
- DET-005: Account Enumeration (T1110.004)
- DET-006: Rapid-Fire Authentication (T1110.001)
- DET-007: Lateral Movement (T1021)
- DET-008: Service Account Abuse (T1078.001)

#### Risk Scoring
- Weighted scoring algorithm (severity x confidence x frequency x context)
- Configurable weights via YAML
- Per-finding and aggregate risk scores
- Score clamping to configurable maximum

#### MITRE ATT&CK Integration
- 7 techniques mapped across detection rules
- Tactic and technique references in all findings
- MITRE references in HTML and JSON reports

#### System Hardening
- Platform-adaptive CIS benchmark checks
- Windows: Firewall (3 profiles), audit policy, Windows Update, password policy
- Linux: File permissions, SSH configuration, firewall status
- Remediation recommendations for every failed check

#### Reporting
- JSON reports with full evidence and metadata
- Styled HTML reports with dark-theme executive dashboard
- Summary statistics (critical/high/medium/low)
- Hardening section in reports
- Configurable output directory and format selection

#### Log Parsing
- Syslog format (Linux auth.log, messages)
- Windows Event Log (key-value format)
- Windows Event Log (XML format)
- 16 Windows Event IDs mapped to security categories
- Automatic format detection

#### CLI Commands
- `sentinelgo analyze` — Full security analysis pipeline
- `sentinelgo scan` — Alias for analyze
- `sentinelgo harden` — Standalone hardening assessment
- `sentinelgo rules list` — List loaded detection rules
- `sentinelgo rules validate` — Validate rule files
- `sentinelgo validate` — Validate configuration
- `sentinelgo version` — Version information

#### Testing & Quality
- 46 unit and integration tests
- 8 performance benchmarks
- Integration tests covering full pipeline
- Synthetic test data generator (1K, 10K events)
- Cross-platform test compatibility

#### Build & Distribution
- Makefile with cross-platform targets
- Windows build script
- Reproducible builds with version embedding
- Single-binary distribution (no runtime dependencies)

### Performance
- 10,000 events: full pipeline in ~264ms
- Collection: 1.6ms/10K events
- Detection: 11ms/10K events (8 rules)
- Minimal memory footprint
