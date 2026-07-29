package detection

import (
	"fmt"
	"strings"
	"time"

	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

type DynamicRule struct {
	def RuleDefinition
}

func NewDynamicRule(def RuleDefinition) *DynamicRule {
	return &DynamicRule{def: def}
}

func (r *DynamicRule) ID() string   { return r.def.ID }
func (r *DynamicRule) Name() string { return r.def.Name }

func (r *DynamicRule) Evaluate(events []models.Event) []models.Finding {
	filtered := r.filterEvents(events)
	if len(filtered) == 0 {
		return nil
	}

	switch {
	case len(r.def.Conditions.UserList) > 0:
		return r.evaluateUserList(filtered)
	case r.def.Conditions.TimeConstraint != nil:
		return r.evaluateTimeConstraint(filtered)
	case r.def.Conditions.DistinctHosts > 0:
		return r.evaluateDistinctHosts(filtered)
	case r.def.Conditions.DistinctTargets > 0:
		return r.evaluateDistinctTargets(filtered)
	case r.def.Conditions.GroupBy == "user":
		return r.evaluateGroupByUser(filtered)
	case r.def.Conditions.GroupBy == "source":
		return r.evaluateGroupBySource(filtered)
	case r.def.Conditions.WindowSeconds > 0:
		return r.evaluateRapidFire(filtered)
	default:
		return r.evaluateThreshold(filtered)
	}
}

func (r *DynamicRule) filterEvents(events []models.Event) []models.Event {
	var filtered []models.Event

	for _, evt := range events {
		if r.def.Conditions.EventCategory != "" && evt.Category != r.def.Conditions.EventCategory {
			continue
		}
		if r.def.Conditions.EventAction != "" && evt.Action != r.def.Conditions.EventAction {
			continue
		}
		if r.def.Conditions.EventOutcome != "" && evt.Outcome != r.def.Conditions.EventOutcome {
			continue
		}

		if r.def.Conditions.MetadataMatch != nil {
			match := true
			for key, val := range r.def.Conditions.MetadataMatch {
				if evtVal, ok := evt.Metadata[key]; !ok || evtVal != val {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		filtered = append(filtered, evt)
	}

	return filtered
}

func (r *DynamicRule) evaluateGroupByUser(events []models.Event) []models.Finding {
	var findings []models.Finding

	userGroups := make(map[string][]models.Event)
	for _, evt := range events {
		if evt.User != "" {
			userGroups[evt.User] = append(userGroups[evt.User], evt)
		}
	}

	window := time.Duration(r.def.Conditions.WindowMinutes) * time.Minute
	for user, userEvents := range userGroups {
		clusters := clusterEvents(userEvents, window)
		for _, cluster := range clusters {
			if len(cluster) >= r.def.Conditions.Threshold {
				findings = append(findings, r.buildFinding(cluster, map[string]string{
					"user":          user,
					"attempt_count": fmt.Sprintf("%d", len(cluster)),
				}))
			}
		}
	}

	return findings
}

func (r *DynamicRule) evaluateGroupBySource(events []models.Event) []models.Finding {
	var findings []models.Finding

	sourceGroups := make(map[string]map[string][]models.Event)
	for _, evt := range events {
		source := evt.Host
		if ip, ok := evt.Metadata["source_ip"]; ok {
			source = ip
		}
		if sourceGroups[source] == nil {
			sourceGroups[source] = make(map[string][]models.Event)
		}
		sourceGroups[source][evt.User] = append(sourceGroups[source][evt.User], evt)
	}

	threshold := r.def.Conditions.DistinctTargets
	if threshold == 0 {
		threshold = r.def.Conditions.Threshold
	}

	for source, userMap := range sourceGroups {
		if len(userMap) >= threshold {
			var evidence []models.Event
			for _, evts := range userMap {
				evidence = append(evidence, evts...)
			}
			findings = append(findings, r.buildFinding(evidence, map[string]string{
				"source":         source,
				"accounts_count": fmt.Sprintf("%d", len(userMap)),
			}))
		}
	}

	return findings
}

func (r *DynamicRule) evaluateDistinctHosts(events []models.Event) []models.Finding {
	var findings []models.Finding

	userHosts := make(map[string]map[string][]models.Event)
	for _, evt := range events {
		if evt.User != "" {
			if userHosts[evt.User] == nil {
				userHosts[evt.User] = make(map[string][]models.Event)
			}
			userHosts[evt.User][evt.Host] = append(userHosts[evt.User][evt.Host], evt)
		}
	}

	for user, hostMap := range userHosts {
		if len(hostMap) >= r.def.Conditions.DistinctHosts {
			var evidence []models.Event
			var hosts []string
			for host, evts := range hostMap {
				hosts = append(hosts, host)
				evidence = append(evidence, evts...)
			}
			findings = append(findings, r.buildFinding(evidence, map[string]string{
				"user":       user,
				"host_count": fmt.Sprintf("%d", len(hostMap)),
				"hosts":      strings.Join(hosts, ","),
			}))
		}
	}

	return findings
}

func (r *DynamicRule) evaluateDistinctTargets(events []models.Event) []models.Finding {
	return r.evaluateGroupBySource(events)
}

func (r *DynamicRule) evaluateTimeConstraint(events []models.Event) []models.Finding {
	var findings []models.Finding

	tc := r.def.Conditions.TimeConstraint
	for _, evt := range events {
		hour := evt.Timestamp.Hour()
		isAfterHours := false

		if tc.AfterHour > tc.BeforeHour {
			isAfterHours = hour >= tc.AfterHour || hour < tc.BeforeHour
		} else {
			isAfterHours = hour >= tc.AfterHour && hour < tc.BeforeHour
		}

		if isAfterHours {
			findings = append(findings, r.buildFinding([]models.Event{evt}, map[string]string{
				"user":       evt.User,
				"login_hour": fmt.Sprintf("%d", hour),
			}))
		}
	}

	return findings
}

func (r *DynamicRule) evaluateUserList(events []models.Event) []models.Finding {
	var findings []models.Finding

	userSet := make(map[string]bool)
	for _, u := range r.def.Conditions.UserList {
		userSet[strings.ToLower(u)] = true
	}

	for _, evt := range events {
		if userSet[strings.ToLower(evt.User)] {
			findings = append(findings, r.buildFinding([]models.Event{evt}, map[string]string{
				"user": evt.User,
				"host": evt.Host,
			}))
		}
	}

	return findings
}

func (r *DynamicRule) evaluateRapidFire(events []models.Event) []models.Finding {
	var findings []models.Finding

	if len(events) < r.def.Conditions.Threshold {
		return findings
	}

	window := time.Duration(r.def.Conditions.WindowSeconds) * time.Second
	for i := 0; i < len(events); i++ {
		var cluster []models.Event
		for j := i; j < len(events); j++ {
			if events[j].Timestamp.Sub(events[i].Timestamp) <= window {
				cluster = append(cluster, events[j])
			} else {
				break
			}
		}

		if len(cluster) >= r.def.Conditions.Threshold {
			findings = append(findings, r.buildFinding(cluster, map[string]string{
				"count":          fmt.Sprintf("%d", len(cluster)),
				"window_seconds": fmt.Sprintf("%d", r.def.Conditions.WindowSeconds),
			}))
			break
		}
	}

	return findings
}

func (r *DynamicRule) evaluateThreshold(events []models.Event) []models.Finding {
	var findings []models.Finding

	if r.def.Conditions.Threshold <= 0 || len(events) >= r.def.Conditions.Threshold {
		for _, evt := range events {
			findings = append(findings, r.buildFinding([]models.Event{evt}, map[string]string{
				"user": evt.User,
				"host": evt.Host,
			}))
		}
	}

	return findings
}

func (r *DynamicRule) buildFinding(evidence []models.Event, metadata map[string]string) models.Finding {
	id := fmt.Sprintf("F-%s-%d", r.def.ID, time.Now().UnixNano())
	if len(evidence) > 0 {
		id = fmt.Sprintf("F-%s-%d", r.def.ID, evidence[0].Timestamp.UnixNano())
	}

	return models.Finding{
		ID:              id,
		RuleID:          r.def.ID,
		RuleName:        r.def.Name,
		Description:     r.def.Description,
		Severity:        ToSeverity(r.def.Severity),
		Confidence:      r.def.Confidence,
		MITRETechnique:  r.def.MITRE.Technique,
		MITRETactic:     r.def.MITRE.Tactic,
		Evidence:        evidence,
		Recommendations: r.def.Recommendations,
		DetectedAt:      time.Now(),
		Metadata:        metadata,
	}
}
