# SentinelGo Detection Rules

## Overview

SentinelGo evaluates security events against a set of detection rules. Rules can be:

- **Built-in** — compiled into the binary (8 rules in v1.0)
- **YAML** — loaded at runtime from the `rules/` directory (no recompile needed)

YAML rules take precedence over built-in rules when any `.yaml` files are present in the rules directory.

---

## Rule File Structure

Each rule is a single `.yaml` file. All fields follow this schema:

```yaml
# Required
id: "DET-001"                       # Unique rule identifier
name: "Brute Force Authentication"  # Human-readable name
description: "Detects repeated failed login attempts from a single user."
enabled: true                       # Set to false to disable without deleting
severity: "high"                    # low | medium | high | critical
confidence: 0.85                    # 0.0 – 1.0

# MITRE ATT&CK mapping (recommended)
mitre:
  technique: "T1110"                # Technique ID
  tactic: "Credential Access"       # Tactic name

# Detection conditions (at least one required)
conditions:
  event_category: "authentication"  # Filter events by category
  event_action: "login"             # Filter by action
  event_outcome: "failure"          # Filter by outcome
  threshold: 5                      # Minimum event count to trigger
  window_seconds: 300               # Time window in seconds (5 minutes)
  group_by: "user"                  # Group events: "user" or "source"
  distinct_targets: 5               # Trigger if ≥N distinct targets in window
  distinct_hosts: 3                 # Trigger if ≥N distinct hosts in window
  user_list:                        # Trigger only for these users
    - "root"
    - "administrator"
  metadata_match:                   # Filter by event metadata key=value
    reason: "invalid_user"
  time_constraint:                  # Only trigger within this time window
    after_hour: 22                  # 22:00 local time
    before_hour: 6                  # 06:00 local time

# Recommendations printed in findings
recommendations:
  - "Lock the affected user account."
  - "Notify the security team."
  - "Review authentication logs."
```

---

## Field Reference

### Top-Level Fields

| Field | Type | Required | Description |
|:------|:----:|:--------:|:------------|
| `id` | string | Yes | Unique identifier, e.g. `DET-001`, `CUSTOM-003` |
| `name` | string | Yes | Short display name |
| `description` | string | No | Longer explanation for reports |
| `enabled` | bool | No | Default `true`. Set `false` to disable. |
| `severity` | string | Yes | `low` · `medium` · `high` · `critical` |
| `confidence` | float | Yes | Detection confidence, `0.0`–`1.0` |
| `mitre` | object | No | MITRE ATT&CK mapping |
| `conditions` | object | Yes | Detection logic |
| `recommendations` | list | No | Remediation steps for reports |

### MITRE Fields

| Field | Type | Description |
|:------|:----:|:------------|
| `mitre.technique` | string | Technique ID, e.g. `T1110`, `T1548.002` |
| `mitre.tactic` | string | Parent tactic, e.g. `Credential Access` |

### Conditions Fields

All conditions fields are optional individually — at least one must be present.

| Field | Type | Description |
|:------|:----:|:------------|
| `event_category` | string | Match events where `category == value` |
| `event_action` | string | Match events where `action == value` |
| `event_outcome` | string | Match events where `outcome == value`: `success`, `failure`, `unknown` |
| `threshold` | int | Minimum number of matching events before triggering |
| `window_seconds` | int | Time window for `threshold` and `group_by` counts |
| `group_by` | string | Group events by `"user"` or `"source"` before applying threshold |
| `distinct_targets` | int | Trigger when ≥N distinct target hosts appear in events |
| `distinct_hosts` | int | Trigger when ≥N distinct source hosts appear in events |
| `user_list` | []string | Filter: only trigger for events from users in this list |
| `metadata_match` | map | Filter: only trigger when event metadata contains key=value pairs |
| `time_constraint` | object | Only evaluate events that occur in this hour range |

### Time Constraint Fields

| Field | Type | Description |
|:------|:----:|:------------|
| `after_hour` | int | Start of sensitive window (24-hour, 0–23), e.g. `22` for 10 PM |
| `before_hour` | int | End of sensitive window (24-hour, 0–23), e.g. `6` for 6 AM |

When `after_hour > before_hour`, the range wraps midnight (e.g. 22→06 means 10 PM to 6 AM).

---

## Event Categories

SentinelGo normalizes all parsed log lines to one of these categories:

| Category | Description | Source Events |
|:---------|:------------|:-------------|
| `authentication` | Login, logout, session events | SSH logins, Windows EventID 4624/4625 |
| `privilege` | Privilege use or escalation | sudo, EventID 4672/4648 |
| `account` | Account management | User creation, deletion, EventID 4720/4726 |
| `process` | Process events | Process creation, EventID 4688 |
| `network` | Network events | Firewall, connections |

---

## Detection Evaluators

SentinelGo automatically selects the correct evaluator based on which conditions fields are set:

| Conditions Present | Evaluator | Trigger |
|:-------------------|:----------|:--------|
| `group_by: user` + `threshold` | GroupByUser | ≥N events per user in window |
| `group_by: source` + `threshold` | GroupBySource | ≥N events per source IP in window |
| `distinct_hosts` | DistinctHosts | ≥N distinct source hosts in all events |
| `distinct_targets` | DistinctTargets | ≥N distinct target hosts in all events |
| `time_constraint` | TimeConstraint | Any matching event in the hour range |
| `user_list` | UserList | Any matching event for a listed user |
| `threshold` only | Threshold | Total matching event count ≥ threshold |
| `threshold` + `window_seconds` (short) | RapidFire | ≥N events within the short time window |
| None of the above | Default | Any matching event (category/action/outcome) |

---

## Built-in Rules (v1.0)

| ID | File | Technique | Trigger Logic |
|:--:|:-----|:---------:|:--------------|
| DET-001 | `brute_force.yaml` | T1110 | ≥5 failures per user in 5 minutes |
| DET-002 | `privilege_escalation.yaml` | T1548 | Any privilege escalation event |
| DET-003 | `invalid_user.yaml` | T1078 | ≥3 invalid_user auth failures |
| DET-004 | `after_hours.yaml` | T1078 | Successful login between 22:00–06:00 |
| DET-005 | `account_enumeration.yaml` | T1110.004 | ≥5 distinct targets from single source |
| DET-006 | `rapid_fire.yaml` | T1110.001 | ≥10 events in 60 seconds |
| DET-007 | `lateral_movement.yaml` | T1021 | ≥3 distinct hosts in event set |
| DET-008 | `service_account.yaml` | T1078.001 | Interactive login by a service account |

---

## Writing Custom Rules

### Example: VPN Login from Unknown Country

```yaml
id: "CUSTOM-001"
name: "VPN Login Outside Corporate Regions"
description: "Detects VPN authentication from unexpected geographic regions."
enabled: true
severity: "medium"
confidence: 0.70
mitre:
  technique: "T1078"
  tactic: "Initial Access"
conditions:
  event_category: "authentication"
  event_action: "vpn_login"
  event_outcome: "success"
  metadata_match:
    region: "unknown"
recommendations:
  - "Verify the user's travel or remote work status."
  - "Request a second factor of authentication."
  - "Notify the user of the login and ask if they recognise it."
```

### Example: Database Account Used During Outage Window

```yaml
id: "CUSTOM-002"
name: "Database Access During Outage Window"
description: "Production DB service accounts used interactively outside maintenance hours."
enabled: true
severity: "high"
confidence: 0.90
mitre:
  technique: "T1078.001"
  tactic: "Persistence"
conditions:
  event_category: "authentication"
  event_outcome: "success"
  user_list:
    - "postgres"
    - "mysql"
    - "oracle"
    - "mongodb"
  time_constraint:
    after_hour: 23
    before_hour: 5
recommendations:
  - "Verify whether a scheduled maintenance window was active."
  - "Review all queries executed during the session."
  - "Rotate service account credentials if access was unauthorized."
```

### Example: Mass Account Lockout

```yaml
id: "CUSTOM-003"
name: "Mass Account Lockout Detected"
description: "High volume of account lockout events suggesting an automated attack."
enabled: true
severity: "critical"
confidence: 0.95
mitre:
  technique: "T1531"
  tactic: "Impact"
conditions:
  event_category: "account"
  event_action: "lockout"
  threshold: 20
  window_seconds: 120
recommendations:
  - "Identify the source IP and block it at the firewall."
  - "Alert the help desk of expected lockout support tickets."
  - "Review whether a credential-stuffing attack is underway."
```

---

## Validation

After creating or editing rules, validate them:

```bash
sentinelgo rules validate
```

Validation checks:
- `id` and `name` are non-empty
- `severity` is one of `low`, `medium`, `high`, `critical`
- `confidence` is between `0.0` and `1.0`
- At least one condition field is present
- `time_constraint.after_hour` and `before_hour` are 0–23

---

## Rule Loading Behavior

1. SentinelGo scans the directory at `detection.rules_path` (default `rules/`) for `*.yaml` files
2. Each file is loaded, parsed, and validated
3. Rules with `enabled: false` are skipped
4. If loading fails for any file, that file is skipped with a warning — other rules continue loading
5. If the directory is missing or empty, the 8 built-in Go rules are used as fallback

To see which rules are active:

```bash
sentinelgo rules list
```

---

## See Also

- [CLI Reference](CLI.md) — command usage
- [Scoring Algorithm](SCORING.md) — how findings are scored
- [MITRE ATT&CK](https://attack.mitre.org/) — technique reference
