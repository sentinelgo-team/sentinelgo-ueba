package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Application ApplicationConfig `yaml:"application"`
	Logging     LoggingConfig     `yaml:"logging"`
	Collector   CollectorConfig   `yaml:"collector"`
	Detection   DetectionConfig   `yaml:"detection"`
	Scoring     ScoringConfig     `yaml:"scoring"`
	Reporting   ReportingConfig   `yaml:"reporting"`
	Hardening   HardeningConfig   `yaml:"hardening"`
}

type ApplicationConfig struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Environment string `yaml:"environment"`
}

type LoggingConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path"`
}

type CollectorConfig struct {
	Sources        []SourceConfig `yaml:"sources"`
	BatchSize      int            `yaml:"batch_size"`
	TimeoutSeconds int            `yaml:"timeout_seconds"`
}

type SourceConfig struct {
	Type   string `yaml:"type"`
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
}

type DetectionConfig struct {
	RulesPath         string `yaml:"rules_path"`
	Enabled           bool   `yaml:"enabled"`
	SeverityThreshold string `yaml:"severity_threshold"`
}

type ScoringConfig struct {
	Algorithm string         `yaml:"algorithm"`
	MaxScore  int            `yaml:"max_score"`
	Weights   ScoringWeights `yaml:"weights"`
}

type ScoringWeights struct {
	Severity   float64 `yaml:"severity"`
	Confidence float64 `yaml:"confidence"`
	Frequency  float64 `yaml:"frequency"`
	Context    float64 `yaml:"context"`
}

type ReportingConfig struct {
	OutputDir              string   `yaml:"output_dir"`
	Formats                []string `yaml:"formats"`
	IncludeEvidence        bool     `yaml:"include_evidence"`
	IncludeRecommendations bool     `yaml:"include_recommendations"`
}

type HardeningConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Benchmarks []string `yaml:"benchmarks"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) validate() error {
	var errs []string

	if c.Application.Name == "" {
		errs = append(errs, "application.name is required")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		errs = append(errs, fmt.Sprintf("logging.level must be one of: debug, info, warn, error (got %q)", c.Logging.Level))
	}

	if c.Scoring.MaxScore <= 0 {
		errs = append(errs, "scoring.max_score must be positive")
	}

	weights := c.Scoring.Weights
	sum := weights.Severity + weights.Confidence + weights.Frequency + weights.Context
	if sum > 0 && (sum < 0.99 || sum > 1.01) {
		errs = append(errs, fmt.Sprintf("scoring.weights must sum to 1.0 (got %.2f)", sum))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config errors:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Collector.BatchSize == 0 {
		c.Collector.BatchSize = 1000
	}
	if c.Collector.TimeoutSeconds == 0 {
		c.Collector.TimeoutSeconds = 30
	}
	if c.Reporting.OutputDir == "" {
		c.Reporting.OutputDir = "reports/"
	}
	if c.Detection.RulesPath == "" {
		c.Detection.RulesPath = "rules/"
	}
}
