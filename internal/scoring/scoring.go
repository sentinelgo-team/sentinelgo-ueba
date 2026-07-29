package scoring

import (
	"math"

	"github.com/sentinelgo/sentinelgo-ueba/internal/config"
	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

type Engine struct {
	maxScore int
	weights  config.ScoringWeights
}

func New(cfg config.ScoringConfig) *Engine {
	return &Engine{
		maxScore: cfg.MaxScore,
		weights:  cfg.Weights,
	}
}

func (e *Engine) Score(f models.Finding) float64 {
	severityScore := severityValue(f.Severity)
	confidenceScore := f.Confidence * 100
	frequencyScore := frequencyValue(len(f.Evidence))
	contextScore := contextValue(f)

	weighted := severityScore*e.weights.Severity +
		confidenceScore*e.weights.Confidence +
		frequencyScore*e.weights.Frequency +
		contextScore*e.weights.Context

	if weighted > float64(e.maxScore) {
		weighted = float64(e.maxScore)
	}
	return math.Round(weighted*10) / 10
}

func (e *Engine) ScoreAll(findings []models.Finding) []models.Finding {
	for i := range findings {
		findings[i].RiskScore = e.Score(findings[i])
	}
	logger.Info("scoring complete", "findings_scored", len(findings))
	return findings
}

func (e *Engine) OverallRisk(findings []models.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	var maxScore float64
	var total float64
	for _, f := range findings {
		if f.RiskScore > maxScore {
			maxScore = f.RiskScore
		}
		total += f.RiskScore
	}

	avg := total / float64(len(findings))
	overall := maxScore*0.6 + avg*0.4

	if overall > float64(e.maxScore) {
		return float64(e.maxScore)
	}
	return math.Round(overall*10) / 10
}

func severityValue(s models.Severity) float64 {
	switch s {
	case models.SeverityCritical:
		return 100
	case models.SeverityHigh:
		return 80
	case models.SeverityMedium:
		return 50
	case models.SeverityLow:
		return 25
	default:
		return 10
	}
}

func frequencyValue(evidenceCount int) float64 {
	switch {
	case evidenceCount >= 20:
		return 100
	case evidenceCount >= 10:
		return 80
	case evidenceCount >= 5:
		return 60
	case evidenceCount >= 3:
		return 40
	default:
		return 20
	}
}

func contextValue(f models.Finding) float64 {
	score := 50.0
	if f.MITRETactic == "Privilege Escalation" {
		score += 20
	}
	if f.MITRETactic == "Lateral Movement" {
		score += 15
	}
	if f.MITRETechnique != "" {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}
