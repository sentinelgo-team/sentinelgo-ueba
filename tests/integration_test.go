package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentinelgo/sentinelgo-ueba/internal/collector"
	"github.com/sentinelgo/sentinelgo-ueba/internal/config"
	"github.com/sentinelgo/sentinelgo-ueba/internal/detection"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
	"github.com/sentinelgo/sentinelgo-ueba/internal/parser"
	"github.com/sentinelgo/sentinelgo-ueba/internal/scoring"
)

func TestFullPipelineSyslog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "auth.log")

	content := `Jan  1 00:00:01 server sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:00:02 server sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:00:03 server sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:00:04 server sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:00:05 server sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:00:06 server sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:00:10 server sshd[1]: Accepted password for admin from 10.0.0.1 port 22 ssh2
Jan  1 00:01:00 server sudo[2]: admin : TTY=pts/0 ; PWD=/root ; COMMAND=/bin/bash
`
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Step 1: Collect
	fc := collector.NewFileCollector(logPath, "syslog")
	rawEvents, err := fc.Collect()
	if err != nil {
		t.Fatalf("collection failed: %v", err)
	}
	if len(rawEvents) != 8 {
		t.Fatalf("expected 8 raw events, got %d", len(rawEvents))
	}

	// Step 2: Parse
	p := parser.New()
	events := p.ParseAll(rawEvents)
	if len(events) != 8 {
		t.Fatalf("expected 8 normalized events, got %d", len(events))
	}

	failCount := 0
	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "failure" {
			failCount++
		}
	}
	if failCount != 6 {
		t.Errorf("expected 6 failed auth events, got %d", failCount)
	}

	// Step 3: Detect
	registry := detection.NewRuleRegistry()
	findings := registry.EvaluateAll(events)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	foundBruteForce := false
	for _, f := range findings {
		if f.RuleID == "DET-001" {
			foundBruteForce = true
			if f.MITRETechnique != "T1110" {
				t.Errorf("expected MITRE T1110, got %s", f.MITRETechnique)
			}
		}
	}
	if !foundBruteForce {
		t.Error("expected brute force detection")
	}

	// Step 4: Score
	cfg := config.ScoringConfig{
		Algorithm: "weighted",
		MaxScore:  100,
		Weights: config.ScoringWeights{
			Severity:   0.4,
			Confidence: 0.3,
			Frequency:  0.2,
			Context:    0.1,
		},
	}
	scorer := scoring.New(cfg)
	for i := range findings {
		findings[i].RiskScore = scorer.Score(findings[i])
		if findings[i].RiskScore <= 0 {
			t.Errorf("expected positive risk score, got %.1f", findings[i].RiskScore)
		}
		if findings[i].RiskScore > 100 {
			t.Errorf("risk score exceeds maximum: %.1f", findings[i].RiskScore)
		}
	}

	overallRisk := scorer.OverallRisk(findings)
	if overallRisk <= 0 || overallRisk > 100 {
		t.Errorf("overall risk out of range: %.1f", overallRisk)
	}
}

func TestFullPipelineWindows(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "windows.log")

	content := `EventID=4625, Timestamp=2025-01-15T08:30:01Z, User=admin, Computer=DC01, Status=failure
EventID=4625, Timestamp=2025-01-15T08:30:02Z, User=admin, Computer=DC01, Status=failure
EventID=4625, Timestamp=2025-01-15T08:30:03Z, User=admin, Computer=DC01, Status=failure
EventID=4625, Timestamp=2025-01-15T08:30:04Z, User=admin, Computer=DC01, Status=failure
EventID=4625, Timestamp=2025-01-15T08:30:05Z, User=admin, Computer=DC01, Status=failure
EventID=4624, Timestamp=2025-01-15T08:31:00Z, User=admin, Computer=DC01, Status=success
EventID=4672, Timestamp=2025-01-15T08:31:01Z, User=admin, Computer=DC01
EventID=4720, Timestamp=2025-01-15T08:35:00Z, User=new_account, Computer=DC01
`
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	fc := collector.NewFileCollector(logPath, "windows")
	rawEvents, err := fc.Collect()
	if err != nil {
		t.Fatalf("collection failed: %v", err)
	}

	p := parser.New()
	events := p.ParseAll(rawEvents)
	if len(events) == 0 {
		t.Fatal("expected parsed events from Windows log")
	}

	registry := detection.NewRuleRegistry()
	findings := registry.EvaluateAll(events)
	if len(findings) == 0 {
		t.Fatal("expected findings from Windows events")
	}
}

func TestDynamicRulesIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	rulePath := filepath.Join(tmpDir, "test_rule.yaml")

	ruleContent := `
id: "CUSTOM-001"
name: "Custom Brute Force"
description: "Custom threshold brute force detection."
enabled: true
severity: "critical"
confidence: 0.95
mitre:
  technique: "T1110"
  tactic: "Credential Access"
conditions:
  event_category: "authentication"
  event_outcome: "failure"
  group_by: "user"
  threshold: 3
  window_minutes: 10
recommendations:
  - "Custom recommendation: investigate immediately."
`
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	registry := detection.NewRuleRegistryFromDirectory(tmpDir)
	if registry.RegisteredRules() != 1 {
		t.Fatalf("expected 1 dynamic rule, got %d", registry.RegisteredRules())
	}

	baseTime := time.Date(2025, 1, 15, 8, 0, 0, 0, time.UTC)
	events := []models.Event{
		{Category: "authentication", Outcome: "failure", User: "target", Timestamp: baseTime},
		{Category: "authentication", Outcome: "failure", User: "target", Timestamp: baseTime.Add(1 * time.Second)},
		{Category: "authentication", Outcome: "failure", User: "target", Timestamp: baseTime.Add(2 * time.Second)},
	}

	findings := registry.EvaluateAll(events)
	if len(findings) == 0 {
		t.Fatal("expected finding from dynamic rule")
	}

	if findings[0].RuleID != "CUSTOM-001" {
		t.Errorf("expected rule ID CUSTOM-001, got %s", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected critical severity, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", findings[0].Confidence)
	}
}

func TestNoFindingsForCleanLogs(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "clean.log")

	content := `Jan  1 09:00:01 server sshd[1]: Accepted password for user1 from 10.0.0.1 port 22 ssh2
Jan  1 09:30:00 server sshd[1]: Accepted password for user2 from 10.0.0.2 port 22 ssh2
`
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	fc := collector.NewFileCollector(logPath, "syslog")
	rawEvents, _ := fc.Collect()

	p := parser.New()
	events := p.ParseAll(rawEvents)

	registry := detection.NewRuleRegistry()
	findings := registry.EvaluateAll(events)

	for _, f := range findings {
		if f.RuleID == "DET-001" {
			t.Error("unexpected brute force finding for clean logs")
		}
	}
}

func TestExternalRulesFallback(t *testing.T) {
	registry := detection.NewRuleRegistryFromDirectory("/nonexistent/path")
	if registry.RegisteredRules() != 8 {
		t.Errorf("expected 8 built-in rules on fallback, got %d", registry.RegisteredRules())
	}
}
