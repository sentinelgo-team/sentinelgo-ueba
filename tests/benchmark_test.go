package tests

import (
	"fmt"
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

func generateSyslogFile(b *testing.B, n int) string {
	b.Helper()
	tmpDir := b.TempDir()
	logPath := filepath.Join(tmpDir, "bench.log")

	file, _ := os.Create(logPath)
	defer file.Close()

	users := []string{"admin", "user1", "user2", "deploy", "root"}
	baseTime := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Second)
		user := users[i%len(users)]
		line := fmt.Sprintf("%s server sshd[%d]: Failed password for %s from 192.168.1.%d port 22 ssh2\n",
			ts.Format("Jan  2 15:04:05"), 1000+i, user, i%255)
		file.WriteString(line)
	}

	return logPath
}

func generateNormalizedEvents(n int) []models.Event {
	events := make([]models.Event, n)
	users := []string{"admin", "user1", "user2", "deploy", "root"}
	hosts := []string{"web01", "web02", "db01"}
	baseTime := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)

	for i := 0; i < n; i++ {
		events[i] = models.Event{
			ID:        fmt.Sprintf("evt-%d", i),
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
			Category:  "authentication",
			Action:    "login",
			Outcome:   "failure",
			User:      users[i%len(users)],
			Host:      hosts[i%len(hosts)],
			Metadata:  map[string]string{},
		}
	}

	return events
}

func generateFindings(n int) []models.Finding {
	findings := make([]models.Finding, n)
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow,
	}

	for i := 0; i < n; i++ {
		findings[i] = models.Finding{
			ID:             fmt.Sprintf("F-%d", i),
			Severity:       severities[i%len(severities)],
			Confidence:     0.7 + float64(i%30)/100,
			MITRETechnique: "T1110",
			MITRETactic:    "Credential Access",
			Evidence:       make([]models.Event, i%10+1),
		}
	}

	return findings
}

func BenchmarkCollection1000(b *testing.B) {
	logPath := generateSyslogFile(b, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fc := collector.NewFileCollector(logPath, "syslog")
		fc.Collect()
	}
}

func BenchmarkCollection10000(b *testing.B) {
	logPath := generateSyslogFile(b, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fc := collector.NewFileCollector(logPath, "syslog")
		fc.Collect()
	}
}

func BenchmarkParsing1000(b *testing.B) {
	logPath := generateSyslogFile(b, 1000)
	fc := collector.NewFileCollector(logPath, "syslog")
	rawEvents, _ := fc.Collect()
	p := parser.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ParseAll(rawEvents)
	}
}

func BenchmarkParsing10000(b *testing.B) {
	logPath := generateSyslogFile(b, 10000)
	fc := collector.NewFileCollector(logPath, "syslog")
	rawEvents, _ := fc.Collect()
	p := parser.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ParseAll(rawEvents)
	}
}

func BenchmarkDetection1000(b *testing.B) {
	events := generateNormalizedEvents(1000)
	registry := detection.NewRuleRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.EvaluateAll(events)
	}
}

func BenchmarkDetection10000(b *testing.B) {
	events := generateNormalizedEvents(10000)
	registry := detection.NewRuleRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.EvaluateAll(events)
	}
}

func BenchmarkScoring100Findings(b *testing.B) {
	findings := generateFindings(100)
	cfg := config.ScoringConfig{
		Algorithm: "weighted",
		MaxScore:  100,
		Weights: config.ScoringWeights{
			Severity: 0.4, Confidence: 0.3, Frequency: 0.2, Context: 0.1,
		},
	}
	scorer := scoring.New(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range findings {
			scorer.Score(findings[j])
		}
	}
}

func BenchmarkFullPipeline1000(b *testing.B) {
	logPath := generateSyslogFile(b, 1000)
	cfg := config.ScoringConfig{
		Algorithm: "weighted",
		MaxScore:  100,
		Weights: config.ScoringWeights{
			Severity: 0.4, Confidence: 0.3, Frequency: 0.2, Context: 0.1,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fc := collector.NewFileCollector(logPath, "syslog")
		rawEvents, _ := fc.Collect()

		p := parser.New()
		events := p.ParseAll(rawEvents)

		registry := detection.NewRuleRegistry()
		findings := registry.EvaluateAll(events)

		scorer := scoring.New(cfg)
		for j := range findings {
			findings[j].RiskScore = scorer.Score(findings[j])
		}
		scorer.OverallRisk(findings)
	}
}

func BenchmarkFullPipeline10000(b *testing.B) {
	logPath := generateSyslogFile(b, 10000)
	cfg := config.ScoringConfig{
		Algorithm: "weighted",
		MaxScore:  100,
		Weights: config.ScoringWeights{
			Severity: 0.4, Confidence: 0.3, Frequency: 0.2, Context: 0.1,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fc := collector.NewFileCollector(logPath, "syslog")
		rawEvents, _ := fc.Collect()

		p := parser.New()
		events := p.ParseAll(rawEvents)

		registry := detection.NewRuleRegistry()
		findings := registry.EvaluateAll(events)

		scorer := scoring.New(cfg)
		for j := range findings {
			findings[j].RiskScore = scorer.Score(findings[j])
		}
		scorer.OverallRisk(findings)
	}
}
