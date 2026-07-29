package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/sentinelgo/sentinelgo-ueba/internal/config"
	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

type Reporter struct {
	outputDir string
	formats   []string
}

func New(cfg config.ReportingConfig) *Reporter {
	return &Reporter{
		outputDir: cfg.OutputDir,
		formats:   cfg.Formats,
	}
}

func (r *Reporter) Generate(scan models.ScanResult, hardening *models.HardeningResult) ([]string, error) {
	if err := os.MkdirAll(r.outputDir, 0750); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	var paths []string
	for _, format := range r.formats {
		switch format {
		case "json":
			path, err := r.generateJSON(scan, hardening)
			if err != nil {
				logger.Error("JSON report failed", "error", err)
				continue
			}
			paths = append(paths, path)
		case "html":
			path, err := r.generateHTML(scan, hardening)
			if err != nil {
				logger.Error("HTML report failed", "error", err)
				continue
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func (r *Reporter) generateJSON(scan models.ScanResult, hardening *models.HardeningResult) (string, error) {
	report := map[string]interface{}{
		"scan":      scan,
		"generated": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	}
	if hardening != nil {
		report["hardening"] = hardening
	}

	path := filepath.Join(r.outputDir, fmt.Sprintf("%s.json", scan.ScanID))
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return "", err
	}

	logger.Info("JSON report generated", "path", path)
	return path, nil
}

func (r *Reporter) generateHTML(scan models.ScanResult, hardening *models.HardeningResult) (string, error) {
	data := struct {
		Scan      models.ScanResult
		Hardening *models.HardeningResult
		Generated string
		Version   string
	}{
		Scan:      scan,
		Hardening: hardening,
		Generated: time.Now().Format("2006-01-02 15:04:05"),
		Version:   "1.0.0",
	}

	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}

	path := filepath.Join(r.outputDir, fmt.Sprintf("%s.html", scan.ScanID))
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", err
	}
	if err := tmpl.Execute(file, data); err != nil {
		return "", err
	}

	logger.Info("HTML report generated", "path", path)
	return path, nil
}

var htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelGo Security Report</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0e17; color: #e2e8f0; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
.header { background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%); border: 1px solid #30363d; border-radius: 12px; padding: 2rem; margin-bottom: 2rem; }
.header h1 { color: #58a6ff; font-size: 1.8rem; margin-bottom: 0.5rem; }
.header .meta { color: #8b949e; font-size: 0.9rem; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.card h2 { color: #58a6ff; margin-bottom: 1rem; font-size: 1.3rem; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.stat { background: #1c2128; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }
.stat .value { font-size: 2rem; font-weight: bold; }
.stat .label { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; }
.critical { color: #f85149; }
.high { color: #f0883e; }
.medium { color: #d29922; }
.low { color: #3fb950; }
.finding { background: #1c2128; border-left: 4px solid #30363d; border-radius: 4px; padding: 1rem; margin-bottom: 1rem; }
.finding.severity-critical { border-left-color: #f85149; }
.finding.severity-high { border-left-color: #f0883e; }
.finding.severity-medium { border-left-color: #d29922; }
.finding.severity-low { border-left-color: #3fb950; }
.finding h3 { margin-bottom: 0.5rem; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-right: 0.5rem; }
.badge-critical { background: #f8514922; color: #f85149; }
.badge-high { background: #f0883e22; color: #f0883e; }
.badge-medium { background: #d2992222; color: #d29922; }
.badge-low { background: #3fb95022; color: #3fb950; }
.mitre { color: #bc8cff; font-family: monospace; font-size: 0.85rem; }
.recommendation { background: #0d1117; border-radius: 4px; padding: 0.75rem; margin-top: 0.5rem; }
.recommendation li { margin-left: 1.5rem; margin-bottom: 0.25rem; color: #8b949e; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; }
.pass { color: #3fb950; }
.fail { color: #f85149; }
.skip { color: #8b949e; }
.footer { text-align: center; color: #484f58; padding: 2rem; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>SentinelGo Security Report</h1>
<div class="meta">Scan ID: {{.Scan.ScanID}} | Generated: {{.Generated}} | Version: {{.Version}}</div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<div class="summary-grid">
<div class="stat"><div class="value">{{.Scan.TotalEvents}}</div><div class="label">Events</div></div>
<div class="stat"><div class="value">{{.Scan.TotalFindings}}</div><div class="label">Findings</div></div>
<div class="stat"><div class="value critical">{{.Scan.Summary.Critical}}</div><div class="label">Critical</div></div>
<div class="stat"><div class="value high">{{.Scan.Summary.High}}</div><div class="label">High</div></div>
<div class="stat"><div class="value medium">{{.Scan.Summary.Medium}}</div><div class="label">Medium</div></div>
<div class="stat"><div class="value low">{{.Scan.Summary.Low}}</div><div class="label">Low</div></div>
</div>
<div class="stat" style="max-width:300px;">
<div class="value" style="color:{{if ge .Scan.RiskScore 75.0}}#f85149{{else if ge .Scan.RiskScore 50.0}}#f0883e{{else if ge .Scan.RiskScore 25.0}}#d29922{{else}}#3fb950{{end}}">{{printf "%.1f" .Scan.RiskScore}}/100</div>
<div class="label">Overall Risk Score</div>
</div>
</div>

{{if .Scan.Findings}}
<div class="card">
<h2>Detection Findings</h2>
{{range .Scan.Findings}}
<div class="finding severity-{{.Severity}}">
<h3><span class="badge badge-{{.Severity}}">{{.Severity}}</span>{{.RuleName}}</h3>
<p>{{.Description}}</p>
<p><span class="mitre">MITRE: {{.MITRETactic}} / {{.MITRETechnique}}</span> | Score: {{printf "%.1f" .RiskScore}} | Confidence: {{printf "%.0f" (mul .Confidence 100)}}%</p>
{{if .Recommendations}}
<div class="recommendation"><strong>Recommendations:</strong><ul>{{range .Recommendations}}<li>{{.}}</li>{{end}}</ul></div>
{{end}}
</div>
{{end}}
</div>
{{end}}

{{if .Hardening}}
<div class="card">
<h2>System Hardening Assessment</h2>
<div class="summary-grid">
<div class="stat"><div class="value">{{.Hardening.TotalChecks}}</div><div class="label">Checks</div></div>
<div class="stat"><div class="value pass">{{.Hardening.Passed}}</div><div class="label">Passed</div></div>
<div class="stat"><div class="value fail">{{.Hardening.Failed}}</div><div class="label">Failed</div></div>
<div class="stat"><div class="value">{{printf "%.1f" .Hardening.Score}}%</div><div class="label">Compliance</div></div>
</div>
<table>
<thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Remediation</th></tr></thead>
<tbody>
{{range .Hardening.Findings}}
<tr><td>{{.Title}}</td><td class="{{.Status}}">{{.Status}}</td><td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td><td>{{.Remediation}}</td></tr>
{{end}}
</tbody>
</table>
</div>
{{end}}

<div class="footer">SentinelGo v{{.Version}} | Report generated {{.Generated}}</div>
</div>
</body>
</html>`
