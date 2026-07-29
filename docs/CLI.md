# SentinelGo CLI Reference

## Overview

SentinelGo is invoked as a single binary. All subcommands follow the pattern:

```
sentinelgo [global-flags] <command> [command-flags] [arguments]
```

---

## Global Flags

These flags apply to every command.

| Flag | Short | Default | Description |
|:-----|:-----:|:-------:|:------------|
| `--config` | `-c` | `configs/sentinelgo.yaml` | Path to the configuration YAML file |

---

## Commands

### `sentinelgo analyze`

Run the full 5-phase security analysis pipeline against one or more log sources.

```
sentinelgo analyze [log-file] [flags]
```

**Arguments**

| Argument | Required | Description |
|:---------|:--------:|:------------|
| `log-file` | No | Path to a single log file. If omitted, sources are read from the config file. |

**Flags**

| Flag | Default | Description |
|:-----|:-------:|:------------|
| `--skip-hardening` | `false` | Skip the CIS system hardening assessment (Phase 5) |

**Pipeline phases**

```
[1/5]  Collect    Read raw lines from one or more log files
[2/5]  Parse      Normalize each line into a structured Event
[3/5]  Detect     Evaluate all loaded detection rules → Findings
[4/5]  Score      Apply weighted risk formula to each Finding
[5/5]  Harden     Run CIS benchmark checks (skipped with --skip-hardening)
```

**Output**

Reports are written to the directory configured in `reporting.output_dir` (default `reports/`):

```
reports/scan-<unix-timestamp>.json
reports/scan-<unix-timestamp>.html
```

**Examples**

```bash
# Analyze a single Linux syslog file
sentinelgo analyze /var/log/auth.log

# Skip CIS checks (faster, no elevated permissions needed)
sentinelgo analyze --skip-hardening testdata/auth.log

# Use a custom config
sentinelgo analyze --config /etc/sentinelgo/prod.yaml /var/log/auth.log

# Analyze Windows Event Log sample
sentinelgo analyze testdata/windows_security.log
```

**Exit codes**

| Code | Meaning |
|:----:|:--------|
| 0 | Analysis completed successfully |
| 1 | Fatal error: config load failed, no events collected, or panic |

---

### `sentinelgo scan`

Alias for `analyze`. Accepts identical flags and arguments.

```
sentinelgo scan [log-file] [flags]
```

Use `scan` as a shorter alias in pipelines and scripts:

```bash
sentinelgo scan /var/log/auth.log --skip-hardening
```

---

### `sentinelgo harden`

Run a standalone CIS benchmark hardening assessment without analyzing any log files.

```
sentinelgo harden
```

**No flags or arguments.**

**Output (stdout)**

```
══════════════════════════════════════════════════════════════
  SentinelGo System Hardening Assessment
  Platform: windows/amd64
══════════════════════════════════════════════════════════════

  CHECK ID    TITLE                              STATUS  SEVERITY
  --------    -----                              ------  --------
  CIS-WIN-001 Firewall enabled (Domain)          pass    high
  CIS-WIN-002 Firewall enabled (Private)         pass    high
  CIS-WIN-006 Password minimum length >= 14      fail    high

══════════════════════════════════════════════════════════════
  Results
══════════════════════════════════════════════════════════════
  Total Checks:  10
  Passed:        8
  Failed:        2
  Compliance:    80.0%
══════════════════════════════════════════════════════════════

  Remediation Recommendations:

  [CIS-WIN-006] Password minimum length >= 14
    -> Set minimum password length to 14+ in Local Security Policy
```

**Platform behavior**

- On **Windows**: runs Windows-specific checks (CIS-WIN-*)
- On **Linux**: runs Linux-specific checks (CIS-LNX-*)
- Checks that require elevated privileges emit `error` status when run without them

**Exit codes**

| Code | Meaning |
|:----:|:--------|
| 0 | Assessment completed (even if checks failed) |
| 1 | Fatal error running the assessment |

---

### `sentinelgo rules list`

List all detection rules currently loaded by the rule registry.

```
sentinelgo rules list [--config path]
```

**Output**

```
══════════════════════════════════════════════════════════════
  SentinelGo Detection Rules
══════════════════════════════════════════════════════════════

  ID        NAME                                 STATUS
  --        ----                                 ------
  DET-001   Brute Force Authentication           active
  DET-002   Privilege Escalation Detection       active
  DET-003   Invalid User Enumeration             active
  DET-004   After-Hours Authentication           active
  DET-005   Account Enumeration                  active
  DET-006   Rapid-Fire Authentication            active
  DET-007   Lateral Movement Detection           active
  DET-008   Service Account Login Detection      active

  Total: 8 rules loaded
  Source: rules/
```

Rules are loaded from the path in `detection.rules_path`. If YAML files are present, they replace the built-in Go rules. If the directory is missing or empty, built-in rules are used automatically.

---

### `sentinelgo rules validate`

Validate all YAML rule files in the configured rules directory, checking for schema errors, required fields, and value constraints.

```
sentinelgo rules validate [--config path]
```

**Output (success)**

```
  Validating rules in: rules/

  8 rules validated successfully

    [valid]     DET-001  [high]      Brute Force Authentication
    [valid]     DET-002  [high]      Privilege Escalation Detection
    [disabled]  DET-003  [medium]    Invalid User Enumeration
```

**Output (failure)**

```
Error: validation failed: rule DET-001: confidence must be between 0.0 and 1.0
```

**What is validated**

| Field | Validation |
|:------|:-----------|
| `id` | Required, non-empty |
| `name` | Required, non-empty |
| `severity` | Must be one of: `low`, `medium`, `high`, `critical` |
| `confidence` | Must be between `0.0` and `1.0` |
| `mitre.technique` | Recommended (warning if missing) |
| `conditions` | At least one condition field required |

**Exit codes**

| Code | Meaning |
|:----:|:--------|
| 0 | All rules valid |
| 1 | One or more rules failed validation |

---

### `sentinelgo validate`

Validate the SentinelGo configuration file (YAML schema and value checks).

```
sentinelgo validate [--config path]
```

**Examples**

```bash
# Validate default config
sentinelgo validate

# Validate an alternate config
sentinelgo validate --config configs/production.yaml
```

**Exit codes**

| Code | Meaning |
|:----:|:--------|
| 0 | Config is valid |
| 1 | Config is invalid — error printed to stderr |

---

### `sentinelgo version`

Display version information including build metadata.

```
sentinelgo version
```

**Output**

```
SentinelGo v1.0.0 (abc1234) built 2025-07-29T12:00:00Z
  Platform: windows/amd64
```

When built without ldflags (e.g. `go run`), commit and date show as `unknown`:

```
SentinelGo v1.0.0 (unknown) built unknown
  Platform: linux/amd64
```

---

## Environment Variables

Configuration values support `${ENV_VAR}` expansion in the YAML file:

```yaml
reporting:
  output_dir: "${SENTINELGO_REPORT_DIR:-reports}"

logging:
  file_path: "${LOG_PATH}"
```

The `:-` default syntax is supported: `${VAR:-default}` expands to `default` when `VAR` is unset.

---

## Exit Code Reference

| Code | Commands | Meaning |
|:----:|:---------|:--------|
| `0` | All | Success — no fatal errors |
| `1` | All | Fatal error — details printed to stderr |

A successful analysis returning findings does **not** set a non-zero exit code. If you want to gate on risk score (e.g., in CI), parse the JSON report:

```bash
sentinelgo analyze auth.log --skip-hardening
risk=$(jq '.risk_score' reports/scan-*.json | tail -1)
if (( $(echo "$risk > 70" | bc -l) )); then
  echo "Risk score too high: $risk"
  exit 1
fi
```

---

## Piping and Scripting

SentinelGo is designed to be scripted. A few patterns:

```bash
# Run analysis and check exit code
sentinelgo analyze /var/log/auth.log && echo "Clean" || echo "Failed"

# Suppress hardening for automated daily runs
sentinelgo scan /var/log/auth.log --skip-hardening >> /dev/null

# Build with version metadata and run
go build -ldflags \
  "-X main.version=1.0.0 -X main.buildDate=$(date -u +%FT%TZ) -X main.gitCommit=$(git rev-parse --short HEAD)" \
  -o sentinelgo ./cmd/sentinelgo/
./sentinelgo version
```

---

## Build with Version Metadata

Use the Makefile for reproducible builds with injected version info:

```bash
make build          # current platform
make release        # all three platforms (Windows + Linux + macOS)
```

Or build manually:

```bash
VERSION=1.0.0
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date -u +%FT%TZ)

go build \
  -ldflags "-X main.version=$VERSION -X main.buildDate=$DATE -X main.gitCommit=$COMMIT" \
  -o sentinelgo \
  ./cmd/sentinelgo/
```

---

## See Also

- [Detection Rules Schema](RULES.md) — how to write custom YAML rules
- [Scoring Algorithm](SCORING.md) — risk score calculation
- [Configuration Reference](../configs/sentinelgo.yaml) — annotated config file
- [CHANGELOG](../CHANGELOG.md) — version history
