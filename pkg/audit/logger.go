package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// Logger is a thread-safe newline-delimited JSON (JSONL) audit event writer.
// Every Log call flushes immediately to the underlying stream.
type Logger struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	writer *bufio.Writer
	closed bool
}

// TargetCount pairs a target or tool name with its blocked occurrence count.
type TargetCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Summary aggregates statistics over a slice of policy.SecurityEvent records.
type Summary struct {
	TotalEvents       int                     `json:"total_events"`
	FirstEvent        time.Time               `json:"first_event,omitempty"`
	LastEvent         time.Time               `json:"last_event,omitempty"`
	BySeverity        map[policy.Severity]int `json:"by_severity"`
	ByCategory        map[string]int          `json:"by_category"`
	ByAction          map[string]int          `json:"by_action"`
	ByRuleID          map[string]int          `json:"by_rule_id"`
	TopBlockedTargets []TargetCount           `json:"top_blocked_targets,omitempty"`
	TopBlockedTools   []TargetCount           `json:"top_blocked_tools,omitempty"`
}

// NewLogger opens (or creates) a JSONL audit log file with 0600 permissions.
func NewLogger(path string) (*Logger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("audit log path cannot be empty")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create audit log directory %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	// Ensure restrictive permissions even when appending to an existing file.
	_ = f.Chmod(0600)

	return &Logger{
		path:   path,
		file:   f,
		writer: bufio.NewWriterSize(f, 16*1024),
	}, nil
}

// NewWriterLogger creates a thread-safe JSONL Logger writing to an arbitrary io.Writer.
func NewWriterLogger(w io.Writer) *Logger {
	if w == nil {
		w = io.Discard
	}
	return &Logger{
		writer: bufio.NewWriterSize(w, 16*1024),
	}
}

// Path returns the filesystem path of the backing audit log file (empty for writer loggers).
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Log serializes ev as a single compact JSON line and flushes immediately.
func (l *Logger) Log(ev policy.SecurityEvent) error {
	if l == nil {
		return nil
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal security event: %w", err)
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("audit logger is closed")
	}
	if _, err := l.writer.Write(data); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	if err := l.writer.Flush(); err != nil {
		return fmt.Errorf("flush audit event: %w", err)
	}
	return nil
}

// Sync flushes buffered output and calls fsync on the backing file when available.
func (l *Logger) Sync() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if err := l.writer.Flush(); err != nil {
		return err
	}
	if l.file != nil {
		return l.file.Sync()
	}
	return nil
}

// Close flushes, syncs, and closes the underlying file handle.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true

	var firstErr error
	if l.writer != nil {
		if err := l.writer.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.file != nil {
		if err := l.file.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := l.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// LoadEvents reads and parses all JSONL security events from a file path.
func LoadEvents(path string) ([]policy.SecurityEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	defer f.Close()
	return ParseEvents(f)
}

// ParseEvents reads newline-delimited policy.SecurityEvent JSON records from r.
func ParseEvents(r io.Reader) ([]policy.SecurityEvent, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var events []policy.SecurityEvent
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev policy.SecurityEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("parse audit log line %d: %w", lineNum, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return events, nil
}

// Summarize computes aggregate counts by severity, category, action, rule ID,
// and ranked top blocked targets and tools.
func Summarize(events []policy.SecurityEvent) Summary {
	s := Summary{
		TotalEvents: len(events),
		BySeverity:  make(map[policy.Severity]int),
		ByCategory:  make(map[string]int),
		ByAction:    make(map[string]int),
		ByRuleID:    make(map[string]int),
	}

	targetCounts := make(map[string]int)
	toolCounts := make(map[string]int)

	for _, ev := range events {
		if !ev.Timestamp.IsZero() {
			if s.FirstEvent.IsZero() || ev.Timestamp.Before(s.FirstEvent) {
				s.FirstEvent = ev.Timestamp
			}
			if s.LastEvent.IsZero() || ev.Timestamp.After(s.LastEvent) {
				s.LastEvent = ev.Timestamp
			}
		}

		sev := ev.Severity
		if sev == "" {
			sev = policy.SeverityInfo
		}
		s.BySeverity[sev]++

		if cat := strings.TrimSpace(ev.Category); cat != "" {
			s.ByCategory[cat]++
		}
		if act := strings.ToLower(strings.TrimSpace(ev.Action)); act != "" {
			s.ByAction[act]++
			if isBlockingAction(act) {
				if tgt := strings.TrimSpace(ev.Target); tgt != "" {
					targetCounts[tgt]++
				}
				if tool := strings.TrimSpace(ev.Tool); tool != "" {
					toolCounts[tool]++
				}
			}
		}
		if rule := strings.TrimSpace(ev.RuleID); rule != "" {
			s.ByRuleID[rule]++
		}
	}

	s.TopBlockedTargets = rankCounts(targetCounts, 10)
	s.TopBlockedTools = rankCounts(toolCounts, 10)
	return s
}

func isBlockingAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "blocked", "block", "denied", "deny", "quarantined", "quarantine", "redacted", "redact":
		return true
	default:
		return false
	}
}

func rankCounts(m map[string]int, limit int) []TargetCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]TargetCount, 0, len(m))
	for name, count := range m {
		out = append(out, TargetCount{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
