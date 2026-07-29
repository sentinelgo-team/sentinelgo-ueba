# SentinelGo Risk Scoring

## Overview

Every detection finding is assigned a numeric **risk score** from 0 to 100 using a weighted multi-factor formula. The individual scores are then combined into a single **overall risk score** for the entire scan.

---

## Per-Finding Score Formula

```
RiskScore = (NormalizedSeverity × 0.40)
          + (Confidence        × 0.30)
          + (FrequencyFactor   × 0.20)
          + (ContextFactor     × 0.10)
```

All terms produce a value in `[0, 1]`. The final score is multiplied by 100 and clamped to `[0, 100]`.

### Weights (default)

| Factor | Weight | Description |
|:-------|:------:|:------------|
| Severity | 0.40 | How dangerous the pattern is |
| Confidence | 0.30 | How certain the detection is |
| Frequency | 0.20 | How many events contributed |
| Context | 0.10 | Environmental risk factors |

Weights sum to `1.0` and are configurable via `configs/sentinelgo.yaml`.

---

## Factor Definitions

### Severity (weight 0.40)

Normalized from the rule's severity tier:

| Tier | Normalized Value | Raw Score Contribution |
|:----:|:----------------:|:----------------------:|
| Critical | 1.00 | 40.0 |
| High | 0.75 | 30.0 |
| Medium | 0.50 | 20.0 |
| Low | 0.25 | 10.0 |

### Confidence (weight 0.30)

Taken directly from the rule's `confidence` field (0.0–1.0). A rule with `confidence: 0.85` contributes `0.85 × 0.30 × 100 = 25.5` points to the final score.

### Frequency (weight 0.20)

Derived from the number of events in the finding's evidence set, capped with logarithmic scaling so a finding with 1,000 events does not dominate over one with 50:

```
FrequencyFactor = min(1.0,  eventCount / 100.0)
```

| Evidence Events | Frequency Factor | Contribution |
|:---------------:|:----------------:|:------------:|
| 1 | 0.01 | 0.2 |
| 5 | 0.05 | 1.0 |
| 10 | 0.10 | 2.0 |
| 50 | 0.50 | 10.0 |
| 100+ | 1.00 | 20.0 |

### Context (weight 0.10)

A qualitative factor for additional environmental signals. In v1.0, context is assigned based on the MITRE tactic:

| MITRE Tactic | Context Factor | Rationale |
|:-------------|:--------------:|:----------|
| Credential Access | 0.80 | Direct threat to identity |
| Privilege Escalation | 0.90 | High-risk system access change |
| Lateral Movement | 0.85 | Indicates active spread |
| Persistence | 0.70 | Long-term access established |
| Initial Access | 0.60 | Perimeter breach attempt |
| Impact | 0.95 | Operational damage likely |
| *(default)* | 0.50 | Unknown or unmapped tactic |

---

## Worked Example

**Rule:** DET-001 Brute Force Authentication  
**Severity:** High → 0.75  
**Confidence:** 0.85  
**Evidence events:** 8  
**MITRE tactic:** Credential Access → context 0.80

```
FrequencyFactor = min(1.0, 8 / 100) = 0.08

RiskScore = (0.75 × 0.40)
          + (0.85 × 0.30)
          + (0.08 × 0.20)
          + (0.80 × 0.10)
          = 0.300 + 0.255 + 0.016 + 0.080
          = 0.651

Final = 0.651 × 100 = 65.1
```

---

## Overall Scan Risk Score

The individual finding scores are combined into one aggregate score using a weighted blend of the maximum and average:

```
OverallRisk = (MaxFindingScore × 0.60) + (AverageFindingScore × 0.40)
```

This formula ensures:
- A single critical finding drives the overall score high (via the max term)
- Many low-severity findings also raise the score (via the average term)

### Example

| Finding | Score |
|:--------|:-----:|
| DET-001 Brute Force | 65.1 |
| DET-004 After Hours | 47.3 |
| DET-007 Lateral Movement | 74.8 |

```
Max     = 74.8
Average = (65.1 + 47.3 + 74.8) / 3 = 62.4

OverallRisk = (74.8 × 0.60) + (62.4 × 0.40)
            = 44.88 + 24.96
            = 69.8
```

---

## Risk Bands

| Score Range | Band | Interpretation |
|:-----------:|:----:|:---------------|
| 80–100 | **Critical** | Immediate investigation required |
| 60–79 | **High** | Investigate within 24 hours |
| 40–59 | **Medium** | Review within 1 week |
| 20–39 | **Low** | Schedule for routine review |
| 0–19 | **Informational** | Log for audit trail |

---

## Customizing Weights

Edit `configs/sentinelgo.yaml`:

```yaml
scoring:
  algorithm: "weighted"
  max_score: 100
  weights:
    severity:   0.40    # increase to make severity more deterministic
    confidence: 0.30    # increase to favor high-confidence rules
    frequency:  0.20    # increase to reward rules with more evidence
    context:    0.10    # increase to emphasize tactic-based context
```

**Constraint:** weights must sum to `1.0`. The scorer validates this at startup.

### Tuning Recommendations

| Goal | Adjustment |
|:-----|:-----------|
| Reduce false-positive noise | Increase `confidence` weight |
| Emphasize high-volume attacks | Increase `frequency` weight |
| Prioritize lateral movement over noisy auth failures | Increase `context` weight |
| Make severity the only differentiator | Set `severity: 1.0`, others: `0.0` |

---

## Zero-Finding Scan

When no findings are produced, `OverallRisk = 0.0`. This is reported as:

```json
{
  "risk_score": 0.0,
  "total_findings": 0,
  "summary": {
    "critical": 0, "high": 0, "medium": 0, "low": 0
  }
}
```

---

## Report Fields

The JSON report includes per-finding scores and the aggregate:

```json
{
  "scan_id": "scan-1753567200",
  "risk_score": 69.8,
  "total_findings": 3,
  "findings": [
    {
      "id": "DET-001",
      "severity": "high",
      "risk_score": 65.1,
      "evidence_count": 8,
      "mitre_technique": "T1110",
      "mitre_tactic": "Credential Access"
    }
  ]
}
```

---

## See Also

- [Detection Rules Schema](RULES.md) — how rules define severity and confidence
- [CLI Reference](CLI.md) — how to run an analysis
- [Configuration Reference](../configs/sentinelgo.yaml) — scoring weight settings
