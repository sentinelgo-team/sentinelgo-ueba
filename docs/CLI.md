# SentinelGo CLI Reference

## Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | `-c` | Path to configuration file | `configs/sentinelgo.yaml` |

## Commands

### `sentinelgo analyze`

Run full security analysis pipeline.

```bash
sentinelgo analyze [log-file] [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--skip-hardening` | Skip system hardening assessment | `false` |

**Examples:**
```bash
sentinelgo analyze /var/log/auth.log
sentinelgo analyze --skip-hardening auth.log
sentinelgo analyze --config custom.yaml /path/to/log
```

---

### `sentinelgo scan`

Alias for `analyze`. Accepts the same flags and arguments.

```bash
sentinelgo scan [log-file] [flags]
```

---

### `sentinelgo harden`

Run standalone system hardening assessment.

```bash
sentinelgo harden
```

Outputs:
- Check results table (pass/fail/error per check)
- Compliance score (percentage)
- Remediation recommendations for failed checks

---

### `sentinelgo rules list`

List all loaded detection rules.

```bash
sentinelgo rules list
```

---

### `sentinelgo rules validate`

Validate YAML rule files in the configured rules directory.

```bash
sentinelgo rules validate
```

---

### `sentinelgo validate`

Validate configuration file.

```bash
sentinelgo validate
sentinelgo validate --config /path/to/config.yaml
```

---

### `sentinelgo version`

Display version information.

```bash
sentinelgo version
```

**Output:**
```
SentinelGo v1.0.0 (abc1234) built 2025-07-29T00:00:00Z
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (configuration, file access, validation) |

## Environment Variables

Configuration values support environment variable expansion:

```yaml
reporting:
  output_dir: "${SENTINELGO_REPORT_DIR}"
```
