package main

import (
	"fmt"
	"os"
	"runtime"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentinelgo/sentinelgo-ueba/internal/collector"
	"github.com/sentinelgo/sentinelgo-ueba/internal/config"
	"github.com/sentinelgo/sentinelgo-ueba/internal/detection"
	"github.com/sentinelgo/sentinelgo-ueba/internal/hardening"
	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
	"github.com/sentinelgo/sentinelgo-ueba/internal/parser"
	"github.com/sentinelgo/sentinelgo-ueba/internal/reporting"
	"github.com/sentinelgo/sentinelgo-ueba/internal/scoring"
)

var (
	version       = "1.0.0"
	buildDate     = "unknown"
	gitCommit     = "unknown"
	configPath    string
	skipHardening bool
)

func main() {
	root := &cobra.Command{
		Use:   "sentinelgo",
		Short: "SentinelGo — Insider Threat Detection & System Hardening",
	}

	root.PersistentFlags().StringVarP(&configPath, "config", "c", "configs/sentinelgo.yaml", "path to configuration file")

	root.AddCommand(versionCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(analyzeCmd())
	root.AddCommand(scanCmd())
	root.AddCommand(rulesCmd())
	root.AddCommand(hardenCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("SentinelGo v%s (%s) built %s\n", version, gitCommit, buildDate)
			fmt.Printf("  Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [log-file]",
		Short: "Scan security logs (alias for analyze)",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runAnalyze,
	}
	cmd.Flags().BoolVar(&skipHardening, "skip-hardening", false, "Skip system hardening assessment")
	return cmd
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := config.Load(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Configuration invalid: %v\n", err)
				return err
			}
			fmt.Println("Configuration is valid.")
			return nil
		},
	}
}

func analyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze [log-file]",
		Short: "Analyze security logs and generate a report",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runAnalyze,
	}
	cmd.Flags().BoolVar(&skipHardening, "skip-hardening", false, "Skip system hardening assessment")
	return cmd
}

func rulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Detection rule management",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all loaded detection rules",
		RunE:  runRulesList,
	}

	validateRulesCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate rule files",
		RunE:  runRulesValidate,
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(validateRulesCmd)
	return cmd
}

func hardenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "harden",
		Short: "Run standalone system hardening assessment",
		RunE:  runHarden,
	}
}

func runAnalyze(cmd *cobra.Command, args []string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n  Unexpected error: %v\n", r)
			fmt.Fprintf(os.Stderr, "  Please report this issue with your log file.\n\n")
			retErr = fmt.Errorf("panic: %v", r)
		}
	}()

	startTime := time.Now()
	scanID := fmt.Sprintf("scan-%d", startTime.Unix())

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := logger.Init(cfg.Logging); err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  SentinelGo Security Analysis")
	fmt.Printf("  Scan ID: %s\n", scanID)
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()

	logger.Info("starting analysis", "version", version, "scan_id", scanID)

	// Phase 1: Collection
	fmt.Println("  [1/5] Collecting events...")

	var sources []config.SourceConfig
	if len(args) > 0 {
		sources = []config.SourceConfig{{Type: "file", Path: args[0], Format: "auto"}}
	} else {
		sources = cfg.Collector.Sources
	}

	if len(sources) == 0 {
		return fmt.Errorf("no log sources configured — provide a file argument or configure sources in sentinelgo.yaml")
	}

	var allRaw []collector.RawEvent
	var collectionErrors int
	for _, src := range sources {
		fc := collector.NewFileCollector(src.Path, src.Format)
		events, err := fc.Collect()
		if err != nil {
			logger.Warn("failed to collect source", "path", src.Path, "error", err)
			fmt.Printf("        ! %s (error: %v)\n", src.Path, err)
			collectionErrors++
			continue
		}
		allRaw = append(allRaw, events...)
		fmt.Printf("        + %s (%d events)\n", src.Path, len(events))
	}

	if len(allRaw) == 0 {
		if collectionErrors > 0 {
			return fmt.Errorf("all %d source(s) failed — check file paths and permissions", collectionErrors)
		}
		return fmt.Errorf("no events collected from any source")
	}

	if collectionErrors > 0 {
		fmt.Printf("        * %d source(s) failed, continuing with available data\n", collectionErrors)
	}

	// Phase 2: Parse
	fmt.Println("  [2/5] Parsing and normalizing...")
	p := parser.New()
	events := p.ParseAll(allRaw)
	fmt.Printf("        + %d events normalized\n", len(events))

	// Phase 3: Detect
	fmt.Println("  [3/5] Running detection rules...")

	var registry *detection.RuleRegistry
	if cfg.Detection.RulesPath != "" {
		registry = detection.NewRuleRegistryFromDirectory(cfg.Detection.RulesPath)
	} else {
		registry = detection.NewRuleRegistry()
	}
	findings := registry.EvaluateAll(events)
	fmt.Printf("        + %d rules evaluated, %d findings\n", registry.RegisteredRules(), len(findings))

	// Phase 4: Score
	fmt.Println("  [4/5] Calculating risk scores...")
	scorer := scoring.New(cfg.Scoring)
	findings = scorer.ScoreAll(findings)
	overallRisk := scorer.OverallRisk(findings)
	fmt.Printf("        + Overall risk: %.1f/100\n", overallRisk)

	// Phase 5: Hardening
	var hardeningResult *models.HardeningResult
	if !skipHardening && cfg.Hardening.Enabled {
		fmt.Println("  [5/5] Assessing system hardening...")
		engine := hardening.NewEngine()
		result := engine.Assess()
		hardeningResult = &result
		fmt.Printf("        + %d checks: %d passed, %d failed (%.1f%%)\n",
			result.TotalChecks, result.Passed, result.Failed, result.Score)
	} else {
		fmt.Println("  [5/5] Hardening assessment skipped")
	}

	// Build result
	summary := buildSummary(findings, overallRisk)
	scanResult := models.ScanResult{
		ScanID:        scanID,
		StartTime:     startTime,
		EndTime:       time.Now(),
		TotalEvents:   len(events),
		TotalFindings: len(findings),
		RiskScore:     overallRisk,
		Findings:      findings,
		Summary:       summary,
	}

	// Generate reports
	fmt.Println()
	fmt.Println("  Generating reports...")
	reporter := reporting.New(cfg.Reporting)
	paths, err := reporter.Generate(scanResult, hardeningResult)
	if err != nil {
		logger.Error("report generation failed", "error", err)
	}
	for _, path := range paths {
		fmt.Printf("        + %s\n", path)
	}

	// Summary
	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  Analysis Complete")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  Events Processed:  %d\n", len(events))
	fmt.Printf("  Findings:          %d\n", len(findings))
	fmt.Printf("  Critical:          %d\n", summary.Critical)
	fmt.Printf("  High:              %d\n", summary.High)
	fmt.Printf("  Medium:            %d\n", summary.Medium)
	fmt.Printf("  Low:               %d\n", summary.Low)
	fmt.Printf("  Risk Score:        %.1f/100\n", overallRisk)
	fmt.Printf("  Duration:          %s\n", elapsed.Round(time.Millisecond))
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()

	return nil
}

func runRulesList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	registry := detection.NewRuleRegistryFromDirectory(cfg.Detection.RulesPath)

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  SentinelGo Detection Rules")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  ID\tNAME\tSTATUS\n")
	fmt.Fprintf(w, "  --\t----\t------\n")

	ids := registry.RuleIDs()
	names := registry.RuleNames()
	for i := range ids {
		fmt.Fprintf(w, "  %s\t%s\tactive\n", ids[i], names[i])
	}
	w.Flush()

	fmt.Printf("\n  Total: %d rules loaded\n", registry.RegisteredRules())
	fmt.Printf("  Source: %s\n\n", cfg.Detection.RulesPath)

	return nil
}

func runRulesValidate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	rulesPath := cfg.Detection.RulesPath
	fmt.Printf("\n  Validating rules in: %s\n\n", rulesPath)

	definitions, err := detection.LoadRulesFromDirectory(rulesPath)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	fmt.Printf("  %d rules validated successfully\n\n", len(definitions))

	for _, def := range definitions {
		status := "valid"
		if !def.Enabled {
			status = "disabled"
		}
		fmt.Printf("    [%s]  %s  [%s]  %s\n", status, def.ID, def.Severity, def.Name)
	}
	fmt.Println()

	return nil
}

func runHarden(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  SentinelGo System Hardening Assessment")
	fmt.Printf("  Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()

	engine := hardening.NewEngine()
	result := engine.Assess()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  CHECK ID\tTITLE\tSTATUS\tSEVERITY\n")
	fmt.Fprintf(w, "  --------\t-----\t------\t--------\n")

	for _, finding := range result.Findings {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			finding.CheckID, finding.Title, finding.Status, finding.Severity)
	}
	w.Flush()

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  Results")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  Total Checks:  %d\n", result.TotalChecks)
	fmt.Printf("  Passed:        %d\n", result.Passed)
	fmt.Printf("  Failed:        %d\n", result.Failed)
	fmt.Printf("  Compliance:    %.1f%%\n", result.Score)
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()

	failedCount := 0
	for _, finding := range result.Findings {
		if finding.Status == "fail" {
			failedCount++
			if failedCount == 1 {
				fmt.Println("  Remediation Recommendations:")
				fmt.Println()
			}
			fmt.Printf("  [%s] %s\n", finding.CheckID, finding.Title)
			if finding.Remediation != "" {
				fmt.Printf("    -> %s\n", finding.Remediation)
			}
			fmt.Println()
		}
	}

	return nil
}

func buildSummary(findings []models.Finding, risk float64) models.Summary {
	s := models.Summary{Score: risk}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityLow:
			s.Low++
		}
	}
	return s
}
