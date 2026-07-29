package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinelgo/sentinelgo-ueba/internal/logger"
)

type RawEvent struct {
	Line    string
	Source  string
	Format  string
	LineNum int
}

type FileCollector struct {
	path   string
	format string
}

func NewFileCollector(path, format string) *FileCollector {
	if format == "" || format == "auto" {
		format = detectFormat(path)
	}
	return &FileCollector{path: path, format: format}
}

func (c *FileCollector) Collect() ([]RawEvent, error) {
	file, err := os.Open(c.path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", c.path, err)
	}
	defer file.Close()

	var events []RawEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		events = append(events, RawEvent{
			Line:    line,
			Source:  c.path,
			Format:  c.format,
			LineNum: lineNum,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", c.path, err)
	}

	logger.Info("collected events", "source", c.path, "format", c.format, "count", len(events))
	return events, nil
}

func detectFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".evtx":
		return "evtx"
	case ".xml":
		return "windows"
	default:
		base := strings.ToLower(filepath.Base(path))
		if strings.Contains(base, "windows") || strings.Contains(base, "security") {
			return "windows"
		}
		return "syslog"
	}
}
