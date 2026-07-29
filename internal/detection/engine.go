package detection

import (
	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

type Rule interface {
	ID() string
	Name() string
	Evaluate(events []models.Event) []models.Finding
}

type RuleRegistry struct {
	rules []Rule
}

func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		rules: builtinRules(),
	}
}

func NewRuleRegistryFromDirectory(dirPath string) *RuleRegistry {
	definitions, err := LoadRulesFromDirectory(dirPath)
	if err != nil {
		logger.Warn("cannot load external rules, using built-in rules", "path", dirPath, "error", err)
		return NewRuleRegistry()
	}

	if len(definitions) == 0 {
		logger.Warn("no external rules found, using built-in rules")
		return NewRuleRegistry()
	}

	var rules []Rule
	for _, def := range definitions {
		rules = append(rules, NewDynamicRule(def))
	}

	logger.Info("rule registry initialized from external rules", "count", len(rules))
	return &RuleRegistry{rules: rules}
}

func (r *RuleRegistry) EvaluateAll(events []models.Event) []models.Finding {
	var findings []models.Finding
	for _, rule := range r.rules {
		results := rule.Evaluate(events)
		findings = append(findings, results...)
	}
	logger.Info("detection complete", "rules_evaluated", len(r.rules), "findings", len(findings))
	return findings
}

func (r *RuleRegistry) RegisteredRules() int {
	return len(r.rules)
}

func (r *RuleRegistry) RuleIDs() []string {
	ids := make([]string, len(r.rules))
	for i, rule := range r.rules {
		ids[i] = rule.ID()
	}
	return ids
}

func (r *RuleRegistry) RuleNames() []string {
	names := make([]string, len(r.rules))
	for i, rule := range r.rules {
		names[i] = rule.Name()
	}
	return names
}

func builtinRules() []Rule {
	return []Rule{
		&BruteForceRule{threshold: 5, windowMinutes: 5},
		&PrivilegeEscalationRule{},
		&InvalidUserRule{threshold: 3, windowMinutes: 10},
		&AfterHoursLoginRule{startHour: 22, endHour: 6},
		&AccountEnumerationRule{threshold: 5, windowMinutes: 5},
		&RapidFireAuthRule{threshold: 10, windowSeconds: 60},
		&LateralMovementRule{threshold: 3, windowMinutes: 15},
		&ServiceAccountAbuseRule{},
	}
}
