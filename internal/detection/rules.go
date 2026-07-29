package detection

import (
	"fmt"
	"strings"
	"time"

	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

// --- Rule 1: Brute Force ---

type BruteForceRule struct {
	threshold     int
	windowMinutes int
}

func (r *BruteForceRule) ID() string   { return "DET-001" }
func (r *BruteForceRule) Name() string { return "Brute Force Authentication" }

func (r *BruteForceRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding

	userFailures := make(map[string][]models.Event)
	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "failure" && evt.User != "" {
			userFailures[evt.User] = append(userFailures[evt.User], evt)
		}
	}

	window := time.Duration(r.windowMinutes) * time.Minute
	for user, failures := range userFailures {
		clusters := clusterEvents(failures, window)
		for _, cluster := range clusters {
			if len(cluster) >= r.threshold {
				findings = append(findings, models.Finding{
					ID:             fmt.Sprintf("F-%s-%s-%d", r.ID(), user, cluster[0].Timestamp.Unix()),
					RuleID:         r.ID(),
					RuleName:       r.Name(),
					Description:    fmt.Sprintf("%d failed login attempts for user '%s' within %d minutes.", len(cluster), user, r.windowMinutes),
					Severity:       models.SeverityHigh,
					Confidence:     0.85,
					MITRETechnique: "T1110",
					MITRETactic:    "Credential Access",
					Evidence:       cluster,
					Recommendations: []string{
						fmt.Sprintf("Investigate account '%s' for potential compromise.", user),
						"Review source IP addresses for known malicious activity.",
						"Consider temporary account lockout if attacks persist.",
						"Enable multi-factor authentication.",
					},
					DetectedAt: time.Now(),
					Metadata: map[string]string{
						"user":          user,
						"attempt_count": fmt.Sprintf("%d", len(cluster)),
					},
				})
			}
		}
	}
	return findings
}

// --- Rule 2: Privilege Escalation ---

type PrivilegeEscalationRule struct{}

func (r *PrivilegeEscalationRule) ID() string   { return "DET-002" }
func (r *PrivilegeEscalationRule) Name() string { return "Privilege Escalation Attempt" }

func (r *PrivilegeEscalationRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding
	for _, evt := range events {
		if evt.Category == "privilege" && evt.Action == "escalation" {
			findings = append(findings, models.Finding{
				ID:             fmt.Sprintf("F-%s-%s-%d", r.ID(), evt.User, evt.Timestamp.Unix()),
				RuleID:         r.ID(),
				RuleName:       r.Name(),
				Description:    fmt.Sprintf("Privilege escalation detected for user '%s' on host '%s'.", evt.User, evt.Host),
				Severity:       models.SeverityHigh,
				Confidence:     0.75,
				MITRETechnique: "T1548",
				MITRETactic:    "Privilege Escalation",
				Evidence:       []models.Event{evt},
				Recommendations: []string{
					fmt.Sprintf("Verify that user '%s' is authorized for elevated privileges.", evt.User),
					"Review command history for suspicious activity.",
				},
				DetectedAt: time.Now(),
				Metadata:   map[string]string{"user": evt.User, "host": evt.Host},
			})
		}
	}
	return findings
}

// --- Rule 3: Invalid User Attempts ---

type InvalidUserRule struct {
	threshold     int
	windowMinutes int
}

func (r *InvalidUserRule) ID() string   { return "DET-003" }
func (r *InvalidUserRule) Name() string { return "Invalid User Enumeration" }

func (r *InvalidUserRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding
	var invalidAttempts []models.Event

	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "failure" {
			if reason, ok := evt.Metadata["reason"]; ok && reason == "invalid_user" {
				invalidAttempts = append(invalidAttempts, evt)
			}
		}
	}

	if len(invalidAttempts) < r.threshold {
		return findings
	}

	window := time.Duration(r.windowMinutes) * time.Minute
	clusters := clusterEvents(invalidAttempts, window)
	for _, cluster := range clusters {
		if len(cluster) >= r.threshold {
			findings = append(findings, models.Finding{
				ID:             fmt.Sprintf("F-%s-%d", r.ID(), cluster[0].Timestamp.Unix()),
				RuleID:         r.ID(),
				RuleName:       r.Name(),
				Description:    fmt.Sprintf("%d login attempts with invalid usernames within %d minutes.", len(cluster), r.windowMinutes),
				Severity:       models.SeverityMedium,
				Confidence:     0.80,
				MITRETechnique: "T1078",
				MITRETactic:    "Initial Access",
				Evidence:       cluster,
				Recommendations: []string{
					"Review source IPs for scanning activity.",
					"Consider implementing account lockout policies.",
				},
				DetectedAt: time.Now(),
				Metadata:   map[string]string{"attempt_count": fmt.Sprintf("%d", len(cluster))},
			})
		}
	}
	return findings
}

// --- Rule 4: After-Hours Login ---

type AfterHoursLoginRule struct {
	startHour int
	endHour   int
}

func (r *AfterHoursLoginRule) ID() string   { return "DET-004" }
func (r *AfterHoursLoginRule) Name() string { return "After-Hours Authentication" }

func (r *AfterHoursLoginRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding
	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "success" {
			hour := evt.Timestamp.Hour()
			if r.isAfterHours(hour) {
				findings = append(findings, models.Finding{
					ID:             fmt.Sprintf("F-%s-%s-%d", r.ID(), evt.User, evt.Timestamp.Unix()),
					RuleID:         r.ID(),
					RuleName:       r.Name(),
					Description:    fmt.Sprintf("User '%s' authenticated at %s (outside business hours).", evt.User, evt.Timestamp.Format("15:04")),
					Severity:       models.SeverityMedium,
					Confidence:     0.60,
					MITRETechnique: "T1078",
					MITRETactic:    "Initial Access",
					Evidence:       []models.Event{evt},
					Recommendations: []string{
						fmt.Sprintf("Verify that user '%s' has a legitimate reason for after-hours access.", evt.User),
						"Correlate with VPN logs and physical access records.",
					},
					DetectedAt: time.Now(),
					Metadata:   map[string]string{"user": evt.User, "login_hour": fmt.Sprintf("%d", hour)},
				})
			}
		}
	}
	return findings
}

func (r *AfterHoursLoginRule) isAfterHours(hour int) bool {
	if r.startHour > r.endHour {
		return hour >= r.startHour || hour < r.endHour
	}
	return hour >= r.startHour && hour < r.endHour
}

// --- Rule 5: Account Enumeration ---

type AccountEnumerationRule struct {
	threshold     int
	windowMinutes int
}

func (r *AccountEnumerationRule) ID() string   { return "DET-005" }
func (r *AccountEnumerationRule) Name() string { return "Account Enumeration" }

func (r *AccountEnumerationRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding

	hostAttempts := make(map[string]map[string][]models.Event)
	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "failure" && evt.User != "" {
			sourceIP := evt.Metadata["source_ip"]
			if sourceIP == "" {
				sourceIP = evt.Host
			}
			if hostAttempts[sourceIP] == nil {
				hostAttempts[sourceIP] = make(map[string][]models.Event)
			}
			hostAttempts[sourceIP][evt.User] = append(hostAttempts[sourceIP][evt.User], evt)
		}
	}

	for source, userMap := range hostAttempts {
		if len(userMap) >= r.threshold {
			var evidence []models.Event
			for _, evts := range userMap {
				evidence = append(evidence, evts...)
			}
			findings = append(findings, models.Finding{
				ID:             fmt.Sprintf("F-%s-%s-%d", r.ID(), source, time.Now().Unix()),
				RuleID:         r.ID(),
				RuleName:       r.Name(),
				Description:    fmt.Sprintf("Failed authentication against %d distinct accounts from source '%s'.", len(userMap), source),
				Severity:       models.SeverityHigh,
				Confidence:     0.85,
				MITRETechnique: "T1110.004",
				MITRETactic:    "Credential Access",
				Evidence:       evidence,
				Recommendations: []string{
					fmt.Sprintf("Block or investigate source '%s'.", source),
					"Review all accounts targeted for compromise.",
					"Implement rate limiting on authentication endpoints.",
				},
				DetectedAt: time.Now(),
				Metadata:   map[string]string{"source": source, "accounts_count": fmt.Sprintf("%d", len(userMap))},
			})
		}
	}
	return findings
}

// --- Rule 6: Rapid-Fire Authentication ---

type RapidFireAuthRule struct {
	threshold     int
	windowSeconds int
}

func (r *RapidFireAuthRule) ID() string   { return "DET-006" }
func (r *RapidFireAuthRule) Name() string { return "Rapid-Fire Authentication" }

func (r *RapidFireAuthRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding
	var authEvents []models.Event

	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "failure" {
			authEvents = append(authEvents, evt)
		}
	}

	if len(authEvents) < r.threshold {
		return findings
	}

	window := time.Duration(r.windowSeconds) * time.Second
	for i := 0; i < len(authEvents); i++ {
		var cluster []models.Event
		for j := i; j < len(authEvents); j++ {
			if authEvents[j].Timestamp.Sub(authEvents[i].Timestamp) <= window {
				cluster = append(cluster, authEvents[j])
			} else {
				break
			}
		}

		if len(cluster) >= r.threshold {
			findings = append(findings, models.Finding{
				ID:             fmt.Sprintf("F-%s-%d", r.ID(), authEvents[i].Timestamp.Unix()),
				RuleID:         r.ID(),
				RuleName:       r.Name(),
				Description:    fmt.Sprintf("%d authentication attempts within %d seconds indicates automated attack.", len(cluster), r.windowSeconds),
				Severity:       models.SeverityCritical,
				Confidence:     0.90,
				MITRETechnique: "T1110.001",
				MITRETactic:    "Credential Access",
				Evidence:       cluster,
				Recommendations: []string{
					"Immediately investigate the source of rapid authentication attempts.",
					"Implement rate limiting or CAPTCHA.",
					"Block the source IP temporarily.",
				},
				DetectedAt: time.Now(),
				Metadata:   map[string]string{"count": fmt.Sprintf("%d", len(cluster))},
			})
			break
		}
	}
	return findings
}

// --- Rule 7: Lateral Movement ---

type LateralMovementRule struct {
	threshold     int
	windowMinutes int
}

func (r *LateralMovementRule) ID() string   { return "DET-007" }
func (r *LateralMovementRule) Name() string { return "Potential Lateral Movement" }

func (r *LateralMovementRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding

	userHosts := make(map[string]map[string][]models.Event)
	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "success" && evt.User != "" {
			if userHosts[evt.User] == nil {
				userHosts[evt.User] = make(map[string][]models.Event)
			}
			userHosts[evt.User][evt.Host] = append(userHosts[evt.User][evt.Host], evt)
		}
	}

	for user, hostMap := range userHosts {
		if len(hostMap) >= r.threshold {
			var evidence []models.Event
			var hosts []string
			for host, evts := range hostMap {
				hosts = append(hosts, host)
				evidence = append(evidence, evts...)
			}
			findings = append(findings, models.Finding{
				ID:             fmt.Sprintf("F-%s-%s-%d", r.ID(), user, time.Now().Unix()),
				RuleID:         r.ID(),
				RuleName:       r.Name(),
				Description:    fmt.Sprintf("User '%s' authenticated to %d distinct hosts: %s.", user, len(hostMap), strings.Join(hosts, ", ")),
				Severity:       models.SeverityHigh,
				Confidence:     0.70,
				MITRETechnique: "T1021",
				MITRETactic:    "Lateral Movement",
				Evidence:       evidence,
				Recommendations: []string{
					fmt.Sprintf("Investigate whether user '%s' has legitimate access to all target hosts.", user),
					"Review session durations and commands executed.",
					"Check for data staging or exfiltration.",
				},
				DetectedAt: time.Now(),
				Metadata:   map[string]string{"user": user, "host_count": fmt.Sprintf("%d", len(hostMap)), "hosts": strings.Join(hosts, ",")},
			})
		}
	}
	return findings
}

// --- Rule 8: Service Account Abuse ---

type ServiceAccountAbuseRule struct{}

func (r *ServiceAccountAbuseRule) ID() string   { return "DET-008" }
func (r *ServiceAccountAbuseRule) Name() string { return "Service Account Interactive Login" }

func (r *ServiceAccountAbuseRule) Evaluate(events []models.Event) []models.Finding {
	var findings []models.Finding

	serviceAccounts := map[string]bool{
		"svc_backup": true, "svc_deploy": true, "svc_monitor": true,
		"deploy": true, "daemon": true, "nobody": true,
		"www-data": true, "postgres": true, "mysql": true, "redis": true,
	}

	for _, evt := range events {
		if evt.Category == "authentication" && evt.Outcome == "success" {
			if serviceAccounts[strings.ToLower(evt.User)] {
				findings = append(findings, models.Finding{
					ID:             fmt.Sprintf("F-%s-%s-%d", r.ID(), evt.User, evt.Timestamp.Unix()),
					RuleID:         r.ID(),
					RuleName:       r.Name(),
					Description:    fmt.Sprintf("Service account '%s' performed an interactive login on '%s'.", evt.User, evt.Host),
					Severity:       models.SeverityHigh,
					Confidence:     0.80,
					MITRETechnique: "T1078.001",
					MITRETactic:    "Persistence",
					Evidence:       []models.Event{evt},
					Recommendations: []string{
						fmt.Sprintf("Investigate why service account '%s' was used interactively.", evt.User),
						"Service accounts should authenticate only via automated processes.",
						"Reset credentials if compromise is suspected.",
					},
					DetectedAt: time.Now(),
					Metadata:   map[string]string{"user": evt.User, "host": evt.Host},
				})
			}
		}
	}
	return findings
}

// --- Utility ---

func clusterEvents(events []models.Event, window time.Duration) [][]models.Event {
	if len(events) == 0 {
		return nil
	}

	var clusters [][]models.Event
	current := []models.Event{events[0]}

	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Sub(events[i-1].Timestamp) <= window {
			current = append(current, events[i])
		} else {
			clusters = append(clusters, current)
			current = []models.Event{events[i]}
		}
	}
	clusters = append(clusters, current)
	return clusters
}
