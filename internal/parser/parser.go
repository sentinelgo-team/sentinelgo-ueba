package parser

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sentinelgo/sentinelgo-ueba/internal/collector"
	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
	"github.com/sentinelgo/sentinelgo-ueba/internal/models"
)

var syslogPattern = regexp.MustCompile(
	`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$`,
)

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (p *Parser) ParseAll(rawEvents []collector.RawEvent) []models.Event {
	var events []models.Event

	for _, raw := range rawEvents {
		event, err := p.Parse(raw)
		if err != nil {
			logger.Debug("skipped unparseable line", "line", raw.LineNum, "error", err)
			continue
		}
		events = append(events, event)
	}

	logger.Info("parsing complete", "input", len(rawEvents), "parsed", len(events))
	return events
}

func (p *Parser) Parse(raw collector.RawEvent) (models.Event, error) {
	switch {
	case raw.Format == "evtx" || raw.Format == "windows":
		return p.parseWindowsEvent(raw)
	case raw.Format == "syslog":
		return p.parseSyslog(raw)
	case strings.HasPrefix(strings.TrimSpace(raw.Line), "<Event"):
		return p.parseWindowsXML(raw)
	case strings.Contains(raw.Line, "EventID="):
		return p.parseWindowsKeyValue(raw)
	default:
		return p.parseSyslog(raw)
	}
}

func (p *Parser) parseSyslog(raw collector.RawEvent) (models.Event, error) {
	matches := syslogPattern.FindStringSubmatch(raw.Line)
	if matches == nil {
		return models.Event{}, fmt.Errorf("line does not match syslog format")
	}

	ts, err := parseSyslogTime(matches[1])
	if err != nil {
		return models.Event{}, fmt.Errorf("parse timestamp: %w", err)
	}

	host := matches[2]
	process := matches[3]
	message := matches[4]

	event := models.Event{
		ID:        generateID(raw.Line),
		Timestamp: ts,
		Source:    process,
		Host:      host,
		Raw:       raw.Line,
		Metadata:  map[string]string{"message": message},
	}

	p.enrichSyslogEvent(&event, message)
	return event, nil
}

func (p *Parser) enrichSyslogEvent(event *models.Event, message string) {
	lower := strings.ToLower(message)
	sourceLower := strings.ToLower(event.Source)

	switch {
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure"):
		event.Category = "authentication"
		event.Action = "login"
		event.Outcome = "failure"
		event.User = extractUser(message)
		if strings.Contains(lower, "invalid user") {
			event.Metadata["reason"] = "invalid_user"
		}

	case strings.Contains(lower, "accepted password") || strings.Contains(lower, "session opened"):
		event.Category = "authentication"
		event.Action = "login"
		event.Outcome = "success"
		event.User = extractUser(message)

	case sourceLower == "sudo" || strings.Contains(lower, "sudo"):
		event.Category = "privilege"
		event.Action = "escalation"
		event.User = extractUser(message)

	case sourceLower == "useradd" || sourceLower == "userdel" || sourceLower == "usermod" ||
		strings.Contains(lower, "useradd") || strings.Contains(lower, "userdel") || strings.Contains(lower, "usermod"):
		event.Category = "account"
		event.Action = "account_change"
		event.User = extractUser(message)

	default:
		event.Category = "system"
		event.Action = "generic"
		event.Outcome = "info"
	}
}

func (p *Parser) parseWindowsEvent(raw collector.RawEvent) (models.Event, error) {
	trimmed := strings.TrimSpace(raw.Line)
	if strings.HasPrefix(trimmed, "<Event") || strings.HasPrefix(trimmed, "<?xml") {
		return p.parseWindowsXML(raw)
	}
	return p.parseWindowsKeyValue(raw)
}

func (p *Parser) parseWindowsKeyValue(raw collector.RawEvent) (models.Event, error) {
	event := models.Event{
		ID:       generateID(raw.Line),
		Source:   raw.Source,
		Metadata: make(map[string]string),
		Raw:      raw.Line,
	}

	parts := strings.Split(raw.Line, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		event.Metadata[key] = value

		switch strings.ToLower(key) {
		case "eventid":
			event.Metadata["event_id"] = value
		case "timestamp", "time":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				event.Timestamp = t
			}
		case "user", "targetusername", "subjectusername":
			if event.User == "" {
				event.User = value
			}
		case "computer", "host":
			event.Host = value
		case "sourceip", "ipaddress":
			event.Metadata["source_ip"] = value
		}
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if eidStr, ok := event.Metadata["event_id"]; ok {
		var eid int
		if _, err := fmt.Sscanf(eidStr, "%d", &eid); err == nil {
			if info, ok := windowsEventIDs[eid]; ok {
				event.Category = info.category
				event.Action = info.action
				event.Outcome = info.outcome
				return event, nil
			}
		}
	}

	event.Category = "windows"
	event.Action = "event"
	event.Outcome = "info"
	return event, nil
}

func (p *Parser) parseWindowsXML(raw collector.RawEvent) (models.Event, error) {
	event := models.Event{
		ID:       generateID(raw.Line),
		Source:   raw.Source,
		Metadata: make(map[string]string),
		Raw:      raw.Line,
	}

	line := raw.Line

	if eid := extractXMLField(line, "EventID"); eid != "" {
		event.Metadata["event_id"] = eid
		var id int
		if _, err := fmt.Sscanf(eid, "%d", &id); err == nil {
			if info, ok := windowsEventIDs[id]; ok {
				event.Category = info.category
				event.Action = info.action
				event.Outcome = info.outcome
			}
		}
	}

	if computer := extractXMLField(line, "Computer"); computer != "" {
		event.Host = computer
	}

	if ts := extractXMLAttr(line, "SystemTime"); ts != "" {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = t
		} else if t, err := time.Parse("2006-01-02T15:04:05.000Z", ts); err == nil {
			event.Timestamp = t
		}
	}

	if user := extractXMLData(line, "TargetUserName"); user != "" {
		event.User = user
	} else if user := extractXMLData(line, "SubjectUserName"); user != "" {
		event.User = user
	}

	if ip := extractXMLData(line, "IpAddress"); ip != "" {
		event.Metadata["source_ip"] = ip
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.Category == "" {
		event.Category = "windows"
		event.Action = "event"
		event.Outcome = "info"
	}

	return event, nil
}

type eventInfo struct {
	category string
	action   string
	outcome  string
}

var windowsEventIDs = map[int]eventInfo{
	4624: {"authentication", "login", "success"},
	4625: {"authentication", "login", "failure"},
	4634: {"authentication", "logout", "success"},
	4648: {"authentication", "explicit_credentials", "attempt"},
	4672: {"privilege", "special_logon", "success"},
	4688: {"process", "creation", "success"},
	4720: {"account", "created", "success"},
	4722: {"account", "enabled", "success"},
	4724: {"account", "password_reset", "attempt"},
	4725: {"account", "disabled", "success"},
	4726: {"account", "deleted", "success"},
	4728: {"group", "member_added", "success"},
	4732: {"group", "member_added", "success"},
	4738: {"account", "modified", "success"},
	4740: {"account", "locked_out", "success"},
	4776: {"authentication", "credential_validation", "attempt"},
}

func extractXMLField(xml, tag string) string {
	re := regexp.MustCompile(`<` + tag + `[^>]*>([^<]+)<`)
	if m := re.FindStringSubmatch(xml); m != nil {
		return m[1]
	}
	return ""
}

func extractXMLAttr(xml, attr string) string {
	re := regexp.MustCompile(attr + `="([^"]+)"`)
	if m := re.FindStringSubmatch(xml); m != nil {
		return m[1]
	}
	return ""
}

func extractXMLData(xml, name string) string {
	re := regexp.MustCompile(`Name="` + name + `"[^>]*>([^<]+)<`)
	if m := re.FindStringSubmatch(xml); m != nil {
		return m[1]
	}
	return ""
}

func extractUser(message string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`for\s+(?:invalid\s+user\s+)?(\w+)\s+from`),
		regexp.MustCompile(`for\s+(?:invalid\s+user\s+)?(\w+)\s*$`),
		regexp.MustCompile(`(?:for|of)\s+user\s+(\w+)`),
		regexp.MustCompile(`user[=:]\s*(\w+)`),
		regexp.MustCompile(`^(\w+)\s*:`),
	}

	for _, re := range patterns {
		if m := re.FindStringSubmatch(message); m != nil {
			return m[1]
		}
	}
	return ""
}

func parseSyslogTime(s string) (time.Time, error) {
	year := time.Now().Year()
	t, err := time.Parse("Jan  2 15:04:05", s)
	if err != nil {
		t, err = time.Parse("Jan 2 15:04:05", s)
		if err != nil {
			return time.Time{}, err
		}
	}
	return t.AddDate(year, 0, 0), nil
}

func generateID(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h[:8])
}
