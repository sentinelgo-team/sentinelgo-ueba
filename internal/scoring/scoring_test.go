package scoring

import (
	"testing"

	"github.com/sentinelgo/sentinelgo-ueba/internal/config"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

func testConfig() config.ScoringConfig {
	return config.ScoringConfig{
		Algorithm: "weighted",
		MaxScore:  100,
		Weights: config.ScoringWeights{
			Severity:   0.4,
			Confidence: 0.3,
			Frequency:  0.2,
			Context:    0.1,
		},
	}
}

func TestScoreCriticalFinding(t *testing.T) {
	engine := New(testConfig())

	finding := models.Finding{
		Severity:       models.SeverityCritical,
		Confidence:     0.90,
		MITRETechnique: "T1110",
		MITRETactic:    "Credential Access",
		Evidence:       make([]models.Event, 10),
	}

	score := engine.Score(finding)
	if score < 70 {
		t.Errorf("expected critical finding score >= 70, got %.1f", score)
	}
	if score > 100 {
		t.Errorf("score exceeds maximum: %.1f", score)
	}
}

func TestScoreLowFinding(t *testing.T) {
	engine := New(testConfig())

	finding := models.Finding{
		Severity:   models.SeverityLow,
		Confidence: 0.50,
		Evidence:   make([]models.Event, 1),
	}

	score := engine.Score(finding)
	if score > 50 {
		t.Errorf("expected low finding score <= 50, got %.1f", score)
	}
}

func TestOverallRiskEmpty(t *testing.T) {
	engine := New(testConfig())
	risk := engine.OverallRisk(nil)
	if risk != 0 {
		t.Errorf("expected 0 risk for no findings, got %.1f", risk)
	}
}

func TestOverallRiskCapped(t *testing.T) {
	engine := New(testConfig())
	findings := []models.Finding{
		{RiskScore: 100},
		{RiskScore: 100},
	}
	risk := engine.OverallRisk(findings)
	if risk > 100 {
		t.Errorf("overall risk should not exceed max_score, got %.1f", risk)
	}
}

func TestSeverityOrdering(t *testing.T) {
	engine := New(testConfig())

	low := models.Finding{Severity: models.SeverityLow, Confidence: 0.5, Evidence: []models.Event{{}}}
	high := models.Finding{Severity: models.SeverityHigh, Confidence: 0.5, Evidence: []models.Event{{}}}

	lowScore := engine.Score(low)
	highScore := engine.Score(high)

	if highScore <= lowScore {
		t.Errorf("high severity (%.1f) should score higher than low (%.1f)", highScore, lowScore)
	}
}

func TestScoreDoesNotExceedMax(t *testing.T) {
	engine := New(testConfig())

	finding := models.Finding{
		Severity:       models.SeverityCritical,
		Confidence:     1.0,
		MITRETechnique: "T1548",
		MITRETactic:    "Privilege Escalation",
		Evidence:       make([]models.Event, 50),
	}

	score := engine.Score(finding)
	if score > 100 {
		t.Errorf("score exceeds max: %.1f", score)
	}
}
