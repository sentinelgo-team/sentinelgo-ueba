package detection

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
	"gopkg.in/yaml.v3"
)

type RuleDefinition struct {
	ID              string     `yaml:"id"`
	Name            string     `yaml:"name"`
	Description     string     `yaml:"description"`
	Enabled         bool       `yaml:"enabled"`
	Severity        string     `yaml:"severity"`
	Confidence      float64    `yaml:"confidence"`
	MITRE           MITREDef   `yaml:"mitre"`
	Conditions      Conditions `yaml:"conditions"`
	Recommendations []string   `yaml:"recommendations"`
}

type MITREDef struct {
	Technique string `yaml:"technique"`
	Tactic    string `yaml:"tactic"`
}

type Conditions struct {
	EventCategory   string            `yaml:"event_category"`
	EventAction     string            `yaml:"event_action"`
	EventOutcome    string            `yaml:"event_outcome"`
	GroupBy         string            `yaml:"group_by"`
	Threshold       int               `yaml:"threshold"`
	WindowMinutes   int               `yaml:"window_minutes"`
	WindowSeconds   int               `yaml:"window_seconds"`
	DistinctTargets int               `yaml:"distinct_targets"`
	DistinctHosts   int               `yaml:"distinct_hosts"`
	MetadataMatch   map[string]string `yaml:"metadata_match"`
	TimeConstraint  *TimeConstraint   `yaml:"time_constraint"`
	UserList        []string          `yaml:"user_list"`
}

type TimeConstraint struct {
	AfterHour  int `yaml:"after_hour"`
	BeforeHour int `yaml:"before_hour"`
}

func LoadRulesFromDirectory(dirPath string) ([]RuleDefinition, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read rules directory %s: %w", dirPath, err)
	}

	var rules []RuleDefinition

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())
		rule, err := LoadRuleFromFile(filePath)
		if err != nil {
			logger.Warn("failed to load rule file", "file", filePath, "error", err)
			continue
		}

		if !rule.Enabled {
			logger.Debug("rule disabled, skipping", "id", rule.ID, "name", rule.Name)
			continue
		}

		rules = append(rules, rule)
	}

	logger.Info("rules loaded from directory", "path", dirPath, "loaded_rules", len(rules))
	return rules, nil
}

func LoadRuleFromFile(filePath string) (RuleDefinition, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return RuleDefinition{}, fmt.Errorf("cannot read rule file: %w", err)
	}

	var rule RuleDefinition
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return RuleDefinition{}, fmt.Errorf("invalid YAML in %s: %w", filePath, err)
	}

	if err := validateRule(rule); err != nil {
		return RuleDefinition{}, fmt.Errorf("invalid rule %s: %w", filePath, err)
	}

	return rule, nil
}

func validateRule(rule RuleDefinition) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.Severity == "" {
		return fmt.Errorf("rule severity is required")
	}

	validSeverities := map[string]bool{
		"low": true, "medium": true, "high": true, "critical": true,
	}
	if !validSeverities[strings.ToLower(rule.Severity)] {
		return fmt.Errorf("invalid severity: %s", rule.Severity)
	}

	if rule.Confidence < 0 || rule.Confidence > 1.0 {
		return fmt.Errorf("confidence must be between 0 and 1.0")
	}

	return nil
}

func ToSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityLow
	}
}
