package detection

import (
	"testing"
	"time"

	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

func TestBruteForceDetection(t *testing.T) {
	base := time.Date(2025, 1, 15, 8, 30, 0, 0, time.UTC)
	events := make([]models.Event, 6)
	for i := range events {
		events[i] = models.Event{
			Category:  "authentication",
			Action:    "login",
			Outcome:   "failure",
			User:      "admin",
			Host:      "server1",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		}
	}

	rule := &BruteForceRule{threshold: 5, windowMinutes: 5}
	findings := rule.Evaluate(events)

	if len(findings) == 0 {
		t.Fatal("expected brute force detection")
	}
	if findings[0].MITRETechnique != "T1110" {
		t.Errorf("expected MITRE T1110, got %s", findings[0].MITRETechnique)
	}
}

func TestBruteForceNoDetectionBelowThreshold(t *testing.T) {
	base := time.Now()
	events := make([]models.Event, 3)
	for i := range events {
		events[i] = models.Event{
			Category:  "authentication",
			Outcome:   "failure",
			User:      "user1",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		}
	}

	rule := &BruteForceRule{threshold: 5, windowMinutes: 5}
	findings := rule.Evaluate(events)

	if len(findings) != 0 {
		t.Errorf("expected no findings below threshold, got %d", len(findings))
	}
}

func TestPrivilegeEscalation(t *testing.T) {
	events := []models.Event{
		{Category: "privilege", Action: "escalation", User: "user1", Host: "server1", Timestamp: time.Now()},
	}

	rule := &PrivilegeEscalationRule{}
	findings := rule.Evaluate(events)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].MITRETechnique != "T1548" {
		t.Errorf("expected MITRE T1548, got %s", findings[0].MITRETechnique)
	}
}

func TestInvalidUserDetection(t *testing.T) {
	base := time.Now()
	events := make([]models.Event, 4)
	for i := range events {
		events[i] = models.Event{
			Category:  "authentication",
			Outcome:   "failure",
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Metadata:  map[string]string{"reason": "invalid_user"},
		}
	}

	rule := &InvalidUserRule{threshold: 3, windowMinutes: 10}
	findings := rule.Evaluate(events)

	if len(findings) == 0 {
		t.Fatal("expected invalid user enumeration detection")
	}
}

func TestAfterHoursLogin(t *testing.T) {
	lateTime := time.Date(2025, 1, 15, 23, 0, 0, 0, time.UTC)
	events := []models.Event{
		{Category: "authentication", Outcome: "success", User: "user1", Timestamp: lateTime},
	}

	rule := &AfterHoursLoginRule{startHour: 22, endHour: 6}
	findings := rule.Evaluate(events)

	if len(findings) == 0 {
		t.Fatal("expected after-hours login detection")
	}
}

func TestAfterHoursLoginDuringBusinessHours(t *testing.T) {
	normalTime := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	events := []models.Event{
		{Category: "authentication", Outcome: "success", User: "user1", Timestamp: normalTime},
	}

	rule := &AfterHoursLoginRule{startHour: 22, endHour: 6}
	findings := rule.Evaluate(events)

	if len(findings) != 0 {
		t.Errorf("expected no findings during business hours, got %d", len(findings))
	}
}

func TestServiceAccountAbuse(t *testing.T) {
	events := []models.Event{
		{Category: "authentication", Outcome: "success", User: "deploy", Host: "web1", Timestamp: time.Now()},
		{Category: "authentication", Outcome: "success", User: "normal_user", Host: "web1", Timestamp: time.Now()},
	}

	rule := &ServiceAccountAbuseRule{}
	findings := rule.Evaluate(events)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (deploy is service account), got %d", len(findings))
	}
	if findings[0].MITRETechnique != "T1078.001" {
		t.Errorf("expected T1078.001, got %s", findings[0].MITRETechnique)
	}
}

func TestLateralMovement(t *testing.T) {
	events := []models.Event{
		{Category: "authentication", Outcome: "success", User: "admin", Host: "server1", Timestamp: time.Now()},
		{Category: "authentication", Outcome: "success", User: "admin", Host: "server2", Timestamp: time.Now()},
		{Category: "authentication", Outcome: "success", User: "admin", Host: "server3", Timestamp: time.Now()},
	}

	rule := &LateralMovementRule{threshold: 3, windowMinutes: 15}
	findings := rule.Evaluate(events)

	if len(findings) == 0 {
		t.Fatal("expected lateral movement detection")
	}
	if findings[0].MITRETechnique != "T1021" {
		t.Errorf("expected T1021, got %s", findings[0].MITRETechnique)
	}
}

func TestRegistryLoadsAllRules(t *testing.T) {
	registry := NewRuleRegistry()
	if registry.RegisteredRules() != 8 {
		t.Errorf("expected 8 registered rules, got %d", registry.RegisteredRules())
	}
}

func TestNoFindingsForBenignActivity(t *testing.T) {
	events := []models.Event{
		{Category: "system", Action: "generic", Outcome: "info", Timestamp: time.Now()},
	}

	registry := NewRuleRegistry()
	findings := registry.EvaluateAll(events)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for benign events, got %d", len(findings))
	}
}
