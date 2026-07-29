package hardening

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

type Check struct {
	ID          string
	Title       string
	Description string
	Severity    models.Severity
	Platform    string
	References  []string
	Evaluate    func() CheckResult
}

type CheckResult struct {
	Status      string
	Details     string
	Remediation string
}

type Engine struct {
	checks []Check
}

func NewEngine() *Engine {
	e := &Engine{}
	switch runtime.GOOS {
	case "windows":
		e.checks = windowsChecks()
	case "linux":
		e.checks = linuxChecks()
	default:
		e.checks = []Check{}
	}
	return e
}

func (e *Engine) Assess() models.HardeningResult {
	result := models.HardeningResult{
		Benchmark:   fmt.Sprintf("CIS-%s-basic", runtime.GOOS),
		TotalChecks: len(e.checks),
	}

	for _, check := range e.checks {
		outcome := check.Evaluate()

		finding := models.HardeningFinding{
			CheckID:     check.ID,
			Title:       check.Title,
			Description: check.Description,
			Status:      outcome.Status,
			Severity:    check.Severity,
			Remediation: outcome.Remediation,
			References:  check.References,
		}

		switch outcome.Status {
		case "pass":
			result.Passed++
		case "fail":
			result.Failed++
		}

		result.Findings = append(result.Findings, finding)
	}

	if result.TotalChecks > 0 {
		result.Score = float64(result.Passed) / float64(result.TotalChecks) * 100
	}

	logger.Info("hardening assessment complete",
		"passed", result.Passed, "failed", result.Failed,
		"score", fmt.Sprintf("%.1f%%", result.Score))
	return result
}

func windowsChecks() []Check {
	return []Check{
		{
			ID:          "CIS-WIN-001",
			Title:       "Windows Firewall enabled (Domain Profile)",
			Description: "Windows Defender Firewall should be enabled for the domain profile.",
			Severity:    models.SeverityHigh,
			Platform:    "windows",
			References:  []string{"CIS Benchmark 9.1.1"},
			Evaluate: func() CheckResult {
				return checkNetshFirewall("domainprofile")
			},
		},
		{
			ID:          "CIS-WIN-002",
			Title:       "Windows Firewall enabled (Private Profile)",
			Description: "Windows Defender Firewall should be enabled for the private profile.",
			Severity:    models.SeverityHigh,
			Platform:    "windows",
			References:  []string{"CIS Benchmark 9.2.1"},
			Evaluate: func() CheckResult {
				return checkNetshFirewall("privateprofile")
			},
		},
		{
			ID:          "CIS-WIN-003",
			Title:       "Windows Firewall enabled (Public Profile)",
			Description: "Windows Defender Firewall should be enabled for the public profile.",
			Severity:    models.SeverityHigh,
			Platform:    "windows",
			References:  []string{"CIS Benchmark 9.3.1"},
			Evaluate: func() CheckResult {
				return checkNetshFirewall("publicprofile")
			},
		},
		{
			ID:          "CIS-WIN-004",
			Title:       "Audit policy covers logon events",
			Description: "Logon and logoff events should be audited.",
			Severity:    models.SeverityMedium,
			Platform:    "windows",
			References:  []string{"CIS Benchmark 17.5.1"},
			Evaluate: func() CheckResult {
				out, err := exec.Command("auditpol", "/get", "/category:Logon/Logoff").Output()
				if err != nil {
					return CheckResult{Status: "error", Details: "Cannot query audit policy. Run as administrator.",
						Remediation: "auditpol /set /category:\"Logon/Logoff\" /success:enable /failure:enable"}
				}
				output := string(out)
				if strings.Contains(output, "Success") || strings.Contains(output, "Failure") {
					return CheckResult{Status: "pass", Details: "Audit policy configured for logon events."}
				}
				return CheckResult{Status: "fail", Details: "Audit policy not configured.",
					Remediation: "auditpol /set /category:\"Logon/Logoff\" /success:enable /failure:enable"}
			},
		},
		{
			ID:          "CIS-WIN-005",
			Title:       "Windows Update service running",
			Description: "Automatic updates should be enabled.",
			Severity:    models.SeverityMedium,
			Platform:    "windows",
			References:  []string{"CIS Benchmark 18.9.101"},
			Evaluate: func() CheckResult {
				out, err := exec.Command("sc", "query", "wuauserv").Output()
				if err != nil {
					return CheckResult{Status: "fail", Details: "Windows Update service not found.",
						Remediation: "sc config wuauserv start=auto && net start wuauserv"}
				}
				if strings.Contains(string(out), "RUNNING") {
					return CheckResult{Status: "pass", Details: "Windows Update service is running."}
				}
				return CheckResult{Status: "fail", Details: "Windows Update service is not running.",
					Remediation: "net start wuauserv"}
			},
		},
		{
			ID:          "CIS-WIN-006",
			Title:       "Password policy minimum length",
			Description: "Passwords should have a minimum length of 14 characters.",
			Severity:    models.SeverityHigh,
			Platform:    "windows",
			References:  []string{"CIS Benchmark 1.1.4"},
			Evaluate: func() CheckResult {
				out, err := exec.Command("net", "accounts").Output()
				if err != nil {
					return CheckResult{Status: "error", Details: "Cannot query password policy.",
						Remediation: "Run as administrator."}
				}
				lines := strings.Split(string(out), "\n")
				for _, line := range lines {
					if strings.Contains(line, "Minimum password length") {
						parts := strings.Fields(line)
						if len(parts) > 0 {
							val := parts[len(parts)-1]
							if val >= "14" {
								return CheckResult{Status: "pass", Details: fmt.Sprintf("Minimum password length: %s", val)}
							}
							return CheckResult{Status: "fail",
								Details:     fmt.Sprintf("Minimum password length is %s (should be >= 14).", val),
								Remediation: "net accounts /minpwlen:14"}
						}
					}
				}
				return CheckResult{Status: "skip", Details: "Could not determine password length policy."}
			},
		},
	}
}

func linuxChecks() []Check {
	return []Check{
		{
			ID:          "CIS-LIN-001",
			Title:       "/etc/passwd permissions",
			Description: "The /etc/passwd file should not be writable by non-root users.",
			Severity:    models.SeverityHigh,
			Platform:    "linux",
			References:  []string{"CIS Benchmark 6.1.2"},
			Evaluate: func() CheckResult {
				return checkFilePermissions("/etc/passwd", "644")
			},
		},
		{
			ID:          "CIS-LIN-002",
			Title:       "/etc/shadow permissions",
			Description: "The /etc/shadow file must be protected.",
			Severity:    models.SeverityCritical,
			Platform:    "linux",
			References:  []string{"CIS Benchmark 6.1.3"},
			Evaluate: func() CheckResult {
				return checkFilePermissions("/etc/shadow", "640")
			},
		},
		{
			ID:          "CIS-LIN-003",
			Title:       "SSH root login disabled",
			Description: "Direct root login via SSH should be disabled.",
			Severity:    models.SeverityHigh,
			Platform:    "linux",
			References:  []string{"CIS Benchmark 5.2.10"},
			Evaluate: func() CheckResult {
				out, err := exec.Command("grep", "-i", "^PermitRootLogin", "/etc/ssh/sshd_config").Output()
				if err != nil {
					return CheckResult{Status: "skip", Details: "Cannot read SSH config."}
				}
				if strings.Contains(strings.ToLower(string(out)), "no") {
					return CheckResult{Status: "pass", Details: "Root login is disabled."}
				}
				return CheckResult{Status: "fail", Details: "Root login may be enabled.",
					Remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"}
			},
		},
		{
			ID:          "CIS-LIN-004",
			Title:       "Firewall active",
			Description: "A host-based firewall should be running.",
			Severity:    models.SeverityHigh,
			Platform:    "linux",
			References:  []string{"CIS Benchmark 3.5.1.1"},
			Evaluate: func() CheckResult {
				out, err := exec.Command("systemctl", "is-active", "ufw").Output()
				if err == nil && strings.TrimSpace(string(out)) == "active" {
					return CheckResult{Status: "pass", Details: "UFW is active."}
				}
				out, err = exec.Command("systemctl", "is-active", "firewalld").Output()
				if err == nil && strings.TrimSpace(string(out)) == "active" {
					return CheckResult{Status: "pass", Details: "firewalld is active."}
				}
				return CheckResult{Status: "fail", Details: "No firewall service detected.",
					Remediation: "Enable firewall: systemctl enable --now ufw"}
			},
		},
	}
}

func checkNetshFirewall(profile string) CheckResult {
	out, err := exec.Command("netsh", "advfirewall", "show", profile, "state").Output()
	if err != nil {
		return CheckResult{Status: "error", Details: "Command execution failed.",
			Remediation: "Run as administrator."}
	}
	if strings.Contains(strings.ToUpper(string(out)), "ON") {
		return CheckResult{Status: "pass", Details: fmt.Sprintf("Firewall %s is ON.", profile)}
	}
	return CheckResult{Status: "fail", Details: fmt.Sprintf("Firewall %s is OFF.", profile),
		Remediation: "netsh advfirewall set allprofiles state on"}
}

func checkFilePermissions(path, expected string) CheckResult {
	out, err := exec.Command("stat", "-c", "%a", path).Output()
	if err != nil {
		return CheckResult{Status: "skip", Details: fmt.Sprintf("Cannot stat %s.", path)}
	}
	perm := strings.TrimSpace(string(out))
	if perm <= expected {
		return CheckResult{Status: "pass", Details: fmt.Sprintf("Permissions: %s (max %s).", perm, expected)}
	}
	return CheckResult{Status: "fail",
		Details:     fmt.Sprintf("Permissions %s exceed maximum %s.", perm, expected),
		Remediation: fmt.Sprintf("chmod %s %s", expected, path)}
}
