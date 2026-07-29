package models

import "time"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Category  string            `json:"category"`
	Action    string            `json:"action"`
	User      string            `json:"user,omitempty"`
	Host      string            `json:"host,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
	Raw       string            `json:"raw,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Finding struct {
	ID              string            `json:"id"`
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	Description     string            `json:"description"`
	Severity        Severity          `json:"severity"`
	Confidence      float64           `json:"confidence"`
	RiskScore       float64           `json:"risk_score"`
	MITRETechnique  string            `json:"mitre_technique,omitempty"`
	MITRETactic     string            `json:"mitre_tactic,omitempty"`
	Evidence        []Event           `json:"evidence"`
	Recommendations []string          `json:"recommendations,omitempty"`
	DetectedAt      time.Time         `json:"detected_at"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type Summary struct {
	Score    float64 `json:"score"`
	Critical int     `json:"critical"`
	High     int     `json:"high"`
	Medium   int     `json:"medium"`
	Low      int     `json:"low"`
}

type ScanResult struct {
	ScanID        string    `json:"scan_id"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	TotalEvents   int       `json:"total_events"`
	TotalFindings int       `json:"total_findings"`
	RiskScore     float64   `json:"risk_score"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
}

type HardeningFinding struct {
	CheckID     string   `json:"check_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Severity    Severity `json:"severity"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

type HardeningResult struct {
	Benchmark   string             `json:"benchmark"`
	TotalChecks int                `json:"total_checks"`
	Passed      int                `json:"passed"`
	Failed      int                `json:"failed"`
	Score       float64            `json:"score"`
	Findings    []HardeningFinding `json:"findings"`
}
