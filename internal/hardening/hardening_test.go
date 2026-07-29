package hardening

import (
	"testing"
)

func TestNewEngineLoadsChecks(t *testing.T) {
	engine := NewEngine()
	if len(engine.checks) == 0 {
		t.Error("expected at least one hardening check to be registered")
	}
}

func TestAssessProducesResult(t *testing.T) {
	engine := NewEngine()
	result := engine.Assess()

	if result.Benchmark == "" {
		t.Error("expected benchmark name to be set")
	}
	if result.TotalChecks == 0 {
		t.Error("expected at least one check to be evaluated")
	}
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("score out of range: %.1f", result.Score)
	}
	if result.Passed+result.Failed > result.TotalChecks {
		t.Errorf("passed + failed exceeds total: %d + %d > %d",
			result.Passed, result.Failed, result.TotalChecks)
	}
}

func TestFindingsPopulated(t *testing.T) {
	engine := NewEngine()
	result := engine.Assess()

	if len(result.Findings) == 0 {
		t.Error("expected hardening findings to be populated")
	}

	for _, f := range result.Findings {
		if f.CheckID == "" {
			t.Error("finding has empty CheckID")
		}
		if f.Title == "" {
			t.Error("finding has empty Title")
		}
		if f.Status == "" {
			t.Error("finding has empty Status")
		}
	}
}
