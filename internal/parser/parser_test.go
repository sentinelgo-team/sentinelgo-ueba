package parser

import (
	"testing"

	"github.com/sentinelgo/sentinelgo-ueba/internal/collector"
)

func TestParseSyslogFailedLogin(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "Jul 28 08:23:01 webserver sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2",
		Source: "auth.log",
		Format: "syslog",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "authentication" {
		t.Errorf("expected category authentication, got %s", event.Category)
	}
	if event.Outcome != "failure" {
		t.Errorf("expected outcome failure, got %s", event.Outcome)
	}
	if event.User != "admin" {
		t.Errorf("expected user admin, got %s", event.User)
	}
}

func TestParseSyslogSuccessLogin(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "Jul 28 08:25:01 webserver sshd[12351]: Accepted password for admin from 192.168.1.100 port 22 ssh2",
		Source: "auth.log",
		Format: "syslog",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "authentication" {
		t.Errorf("expected category authentication, got %s", event.Category)
	}
	if event.Outcome != "success" {
		t.Errorf("expected outcome success, got %s", event.Outcome)
	}
}

func TestParseSyslogSudo(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "Jul 28 09:01:00 webserver sudo[13001]: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
		Source: "auth.log",
		Format: "syslog",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "privilege" {
		t.Errorf("expected category privilege, got %s", event.Category)
	}
	if event.Action != "escalation" {
		t.Errorf("expected action escalation, got %s", event.Action)
	}
}

func TestParseSyslogUseradd(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "Jul 28 09:15:00 webserver useradd[13100]: new user: name=backdoor, UID=1001, GID=1001",
		Source: "auth.log",
		Format: "syslog",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "account" {
		t.Errorf("expected category account, got %s", event.Category)
	}
}

func TestParseSyslogInvalidLine(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "this is not a valid syslog line",
		Source: "auth.log",
		Format: "syslog",
	}

	_, err := p.Parse(raw)
	if err == nil {
		t.Error("expected error for invalid syslog line")
	}
}

func TestParseSyslogInvalidUser(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "Jul 28 10:00:01 dbserver sshd[14001]: Failed password for invalid user test from 10.0.0.50 port 22 ssh2",
		Source: "auth.log",
		Format: "syslog",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Metadata["reason"] != "invalid_user" {
		t.Errorf("expected reason=invalid_user, got %q", event.Metadata["reason"])
	}
	if event.User != "test" {
		t.Errorf("expected user test, got %s", event.User)
	}
}

func TestParseWindowsKeyValue(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "EventID=4625, Timestamp=2025-01-15T08:30:01Z, User=admin, Computer=WORKSTATION01, Status=failure, SourceIP=192.168.1.200",
		Source: "windows.log",
		Format: "windows",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "authentication" {
		t.Errorf("expected category authentication, got %s", event.Category)
	}
	if event.Outcome != "failure" {
		t.Errorf("expected outcome failure, got %s", event.Outcome)
	}
	if event.User != "admin" {
		t.Errorf("expected user admin, got %s", event.User)
	}
	if event.Host != "WORKSTATION01" {
		t.Errorf("expected host WORKSTATION01, got %s", event.Host)
	}
}

func TestParseWindowsSuccess(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "EventID=4624, Timestamp=2025-01-15T08:31:00Z, User=admin, Computer=WORKSTATION01, Status=success",
		Source: "windows.log",
		Format: "windows",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "authentication" {
		t.Errorf("expected authentication, got %s", event.Category)
	}
	if event.Outcome != "success" {
		t.Errorf("expected success, got %s", event.Outcome)
	}
}

func TestParseWindowsPrivilege(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "EventID=4672, Timestamp=2025-01-15T08:31:01Z, User=admin, Computer=WORKSTATION01",
		Source: "windows.log",
		Format: "windows",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "privilege" {
		t.Errorf("expected privilege, got %s", event.Category)
	}
}

func TestParseWindowsAccountCreation(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   "EventID=4720, Timestamp=2025-01-15T08:35:00Z, User=backdoor_acct, Computer=WORKSTATION01",
		Source: "windows.log",
		Format: "windows",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "account" {
		t.Errorf("expected account, got %s", event.Category)
	}
	if event.Action != "created" {
		t.Errorf("expected created, got %s", event.Action)
	}
}

func TestParseWindowsXML(t *testing.T) {
	p := New()
	raw := collector.RawEvent{
		Line:   `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><TimeCreated SystemTime="2025-01-15T10:00:00.000Z"/><Computer>DC01</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">testuser</Data><Data Name="IpAddress">10.0.0.1</Data></EventData></Event>`,
		Source: "windows.evtx",
		Format: "evtx",
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Category != "authentication" {
		t.Errorf("expected authentication, got %s", event.Category)
	}
	if event.User != "testuser" {
		t.Errorf("expected user testuser, got %s", event.User)
	}
	if event.Host != "DC01" {
		t.Errorf("expected host DC01, got %s", event.Host)
	}
}

func TestParseAll(t *testing.T) {
	p := New()
	rawEvents := []collector.RawEvent{
		{Line: "Jul 28 08:23:01 web sshd[1]: Failed password for admin from 1.2.3.4 port 22 ssh2", Format: "syslog"},
		{Line: "not valid", Format: "syslog"},
		{Line: "EventID=4625, Timestamp=2025-01-15T08:30:01Z, User=test, Computer=SRV01", Format: "windows"},
	}

	events := p.ParseAll(rawEvents)
	if len(events) != 2 {
		t.Errorf("expected 2 parsed events (1 invalid skipped), got %d", len(events))
	}
}
