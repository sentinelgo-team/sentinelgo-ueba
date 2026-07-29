package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	content := `
application:
  name: "TestApp"
  version: "0.1.0"
  environment: "test"
logging:
  level: "debug"
  format: "text"
  output: "console"
  file_path: "test.log"
collector:
  sources:
    - type: "file"
      path: "testdata/auth.log"
      format: "syslog"
  batch_size: 500
  timeout_seconds: 10
detection:
  rules_path: "rules/"
  enabled: true
  severity_threshold: "low"
scoring:
  algorithm: "weighted"
  max_score: 100
  weights:
    severity: 0.4
    confidence: 0.3
    frequency: 0.2
    context: 0.1
reporting:
  output_dir: "reports/"
  formats:
    - "json"
  include_evidence: true
  include_recommendations: true
hardening:
  enabled: false
  benchmarks: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	if cfg.Application.Name != "TestApp" {
		t.Errorf("expected name TestApp, got %s", cfg.Application.Name)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected level debug, got %s", cfg.Logging.Level)
	}
	if cfg.Scoring.MaxScore != 100 {
		t.Errorf("expected max_score 100, got %d", cfg.Scoring.MaxScore)
	}
	if len(cfg.Collector.Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(cfg.Collector.Sources))
	}
}

func TestLoadInvalidLevel(t *testing.T) {
	content := `
application:
  name: "Test"
  version: "0.1.0"
logging:
  level: "invalid"
scoring:
  max_score: 100
  weights:
    severity: 0.4
    confidence: 0.3
    frequency: 0.2
    context: 0.1
`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid log level")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWeightValidation(t *testing.T) {
	content := `
application:
  name: "Test"
  version: "0.1.0"
logging:
  level: "info"
scoring:
  max_score: 100
  weights:
    severity: 0.5
    confidence: 0.5
    frequency: 0.5
    context: 0.5
`
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for weights summing to 2.0")
	}
}
