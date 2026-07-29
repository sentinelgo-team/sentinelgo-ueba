package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRuleFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	rulePath := filepath.Join(tmpDir, "test_rule.yaml")

	content := `
id: "TEST-001"
name: "Test Rule"
description: "A test rule for unit testing."
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
  threshold: 5
  window_minutes: 5
recommendations:
  - "Investigate the account."
`
	if err := os.WriteFile(rulePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test rule: %v", err)
	}

	rule, err := LoadRuleFromFile(rulePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rule.ID != "TEST-001" {
		t.Errorf("expected ID TEST-001, got %s", rule.ID)
	}
	if rule.Name != "Test Rule" {
		t.Errorf("expected name 'Test Rule', got %s", rule.Name)
	}
	if rule.Severity != "high" {
		t.Errorf("expected severity high, got %s", rule.Severity)
	}
	if rule.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", rule.Confidence)
	}
	if rule.MITRE.Technique != "T1110" {
		t.Errorf("expected MITRE T1110, got %s", rule.MITRE.Technique)
	}
	if rule.Conditions.Threshold != 5 {
		t.Errorf("expected threshold 5, got %d", rule.Conditions.Threshold)
	}
	if len(rule.Recommendations) != 1 {
		t.Errorf("expected 1 recommendation, got %d", len(rule.Recommendations))
	}
}

func TestLoadRuleInvalidSeverity(t *testing.T) {
	tmpDir := t.TempDir()
	rulePath := filepath.Join(tmpDir, "bad_rule.yaml")

	content := `
id: "BAD-001"
name: "Bad Rule"
description: "Invalid severity."
enabled: true
severity: "extreme"
confidence: 0.5
conditions:
  threshold: 1
`
	if err := os.WriteFile(rulePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test rule: %v", err)
	}

	_, err := LoadRuleFromFile(rulePath)
	if err == nil {
		t.Fatal("expected validation error for invalid severity")
	}
}

func TestLoadRuleMissingID(t *testing.T) {
	tmpDir := t.TempDir()
	rulePath := filepath.Join(tmpDir, "no_id.yaml")

	content := `
name: "No ID Rule"
description: "Missing ID field."
enabled: true
severity: "low"
confidence: 0.5
`
	if err := os.WriteFile(rulePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test rule: %v", err)
	}

	_, err := LoadRuleFromFile(rulePath)
	if err == nil {
		t.Fatal("expected validation error for missing ID")
	}
}

func TestLoadRulesFromDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	rule1 := `
id: "DIR-001"
name: "Rule One"
description: "First rule."
enabled: true
severity: "high"
confidence: 0.8
conditions:
  event_category: "authentication"
  threshold: 5
`
	rule2 := `
id: "DIR-002"
name: "Rule Two"
description: "Second rule (disabled)."
enabled: false
severity: "medium"
confidence: 0.6
conditions:
  threshold: 3
`
	rule3 := `
id: "DIR-003"
name: "Rule Three"
description: "Third rule."
enabled: true
severity: "low"
confidence: 0.5
conditions:
  threshold: 1
`

	os.WriteFile(filepath.Join(tmpDir, "rule1.yaml"), []byte(rule1), 0644)
	os.WriteFile(filepath.Join(tmpDir, "rule2.yaml"), []byte(rule2), 0644)
	os.WriteFile(filepath.Join(tmpDir, "rule3.yaml"), []byte(rule3), 0644)
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not a rule"), 0644)

	rules, err := LoadRulesFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 2 {
		t.Errorf("expected 2 enabled rules, got %d", len(rules))
	}
}

func TestLoadRulesFromMissingDirectory(t *testing.T) {
	_, err := LoadRulesFromDirectory("/nonexistent/rules/path")
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestDynamicRuleEvaluate(t *testing.T) {
	def := RuleDefinition{
		ID:         "DYN-001",
		Name:       "Dynamic Test",
		Severity:   "high",
		Confidence: 0.9,
		MITRE:      MITREDef{Technique: "T1110", Tactic: "Credential Access"},
		Conditions: Conditions{
			EventCategory: "authentication",
			EventOutcome:  "failure",
			GroupBy:       "user",
			Threshold:     2,
			WindowMinutes: 5,
		},
	}

	rule := NewDynamicRule(def)

	if rule.ID() != "DYN-001" {
		t.Errorf("expected ID DYN-001, got %s", rule.ID())
	}
	if rule.Name() != "Dynamic Test" {
		t.Errorf("expected name Dynamic Test, got %s", rule.Name())
	}
}
