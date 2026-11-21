package mcpproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// LockfileVersion is the schema version written into mcpgate.lock files.
const LockfileVersion = "mcpgate-lock/v1"

// LockedTool stores the pinned SHA-256 fingerprint for a single MCP tool definition.
type LockedTool struct {
	Name        string    `json:"name"`
	SHA256      string    `json:"sha256"`
	Description string    `json:"description,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// LockViolation describes a rug-pull mutation or lockfile mismatch for an MCP tool.
type LockViolation struct {
	Server       string          `json:"server"`
	ToolName     string          `json:"tool_name"`
	Kind         string          `json:"kind"` // mid_session_mutation | hash_mismatch | unpinned_tool
	RuleID       string          `json:"rule_id"`
	Severity     policy.Severity `json:"severity"`
	ExpectedHash string          `json:"expected_hash,omitempty"`
	ActualHash   string          `json:"actual_hash"`
	Message      string          `json:"message"`
}

// Lockfile pins canonical SHA-256 hashes per (server, tool_name) and detects mid-session
// schema mutations (rug-pull attacks).
type Lockfile struct {
	Version   string                           `json:"version"`
	UpdatedAt time.Time                        `json:"updated_at"`
	Servers   map[string]map[string]LockedTool `json:"servers"`

	mu      sync.RWMutex
	path    string
	session map[string]map[string]string
}

type canonicalToolPayload struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ComputeToolHash returns the canonical lowercase hex SHA-256 digest of a tool's
// normalized (name, description, inputSchema). Go's encoding/json deterministically sorts
// all nested map keys lexicographically.
func ComputeToolHash(tool ToolDefinition) string {
	schema := tool.InputSchema
	if schema == nil {
		schema = map[string]any{}
	}
	payload := canonicalToolPayload{
		Name:        strings.TrimSpace(tool.Name),
		Description: tool.Description,
		InputSchema: schema,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NewLockfile creates an empty in-memory Lockfile bound to path (which may be empty for session-only pinning).
func NewLockfile(path string) *Lockfile {
	return &Lockfile{
		Version:   LockfileVersion,
		UpdatedAt: time.Now().UTC(),
		Servers:   make(map[string]map[string]LockedTool),
		path:      path,
		session:   make(map[string]map[string]string),
	}
}

// LoadLockfile reads an existing mcpgate.lock JSON file from disk.
func LoadLockfile(path string) (*Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile %q: %w", path, err)
	}
	lf := NewLockfile(path)
	if err := json.Unmarshal(data, lf); err != nil {
		return nil, fmt.Errorf("parse lockfile %q: %w", path, err)
	}
	if lf.Version == "" {
		lf.Version = LockfileVersion
	}
	if lf.Servers == nil {
		lf.Servers = make(map[string]map[string]LockedTool)
	}
	lf.path = path
	lf.session = make(map[string]map[string]string)
	return lf, nil
}

// LoadOrCreateLockfile loads path if it exists, or returns a fresh Lockfile bound to path if missing.
func LoadOrCreateLockfile(path string) (*Lockfile, error) {
	if strings.TrimSpace(path) == "" {
		return NewLockfile(""), nil
	}
	lf, err := LoadLockfile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewLockfile(path), nil
		}
		return nil, err
	}
	return lf, nil
}

// Path returns the filesystem path bound to this lockfile.
func (l *Lockfile) Path() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.path
}

// Save atomically persists the lockfile to its configured path.
func (l *Lockfile) Save() error {
	l.mu.RLock()
	p := l.path
	l.mu.RUnlock()
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("lockfile has no path configured")
	}
	return l.SaveTo(p)
}

// SaveTo atomically writes the lockfile to destPath using a temp file in the same directory and rename.
func (l *Lockfile) SaveTo(destPath string) error {
	l.mu.Lock()
	l.Version = LockfileVersion
	l.UpdatedAt = time.Now().UTC()
	if l.Servers == nil {
		l.Servers = make(map[string]map[string]LockedTool)
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		l.mu.Unlock()
		return fmt.Errorf("marshal lockfile: %w", err)
	}
	l.path = destPath
	l.mu.Unlock()

	data = append(data, '\n')

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create lockfile directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".mcpgate-lock-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp lockfile: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp lockfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp lockfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp lockfile: %w", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("atomic rename lockfile to %q: %w", destPath, err)
	}
	cleanup = false
	return nil
}

// LockTools pins or updates all provided tools for a server in memory.
func (l *Lockfile) LockTools(server string, tools []ToolDefinition) {
	srv := normalizeServerKey(server)
	now := time.Now().UTC()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.Servers == nil {
		l.Servers = make(map[string]map[string]LockedTool)
	}
	if l.Servers[srv] == nil {
		l.Servers[srv] = make(map[string]LockedTool)
	}
	if l.session[srv] == nil {
		l.session[srv] = make(map[string]string)
	}

	for _, t := range tools {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			continue
		}
		h := ComputeToolHash(t)
		existing, ok := l.Servers[srv][name]
		firstSeen := now
		if ok && !existing.FirstSeen.IsZero() {
			firstSeen = existing.FirstSeen
		}
		l.Servers[srv][name] = LockedTool{
			Name:        name,
			SHA256:      h,
			Description: truncateEvidence(t.Description, 160),
			FirstSeen:   firstSeen,
			UpdatedAt:   now,
		}
		l.session[srv][name] = h
	}
	l.UpdatedAt = now
}

// VerifyTools checks a server's tools against both the active session baseline (detecting
// mid-session rug-pull mutations) and the persisted lockfile pins.
// Supported modes: "off", "warn", "enforce", "update".
func (l *Lockfile) VerifyTools(server string, tools []ToolDefinition, mode string) []LockViolation {
	normMode := strings.ToLower(strings.TrimSpace(mode))
	if normMode == "" || normMode == "off" {
		return nil
	}

	srv := normalizeServerKey(server)
	now := time.Now().UTC()

	l.mu.Lock()
	if l.Servers == nil {
		l.Servers = make(map[string]map[string]LockedTool)
	}
	if l.session == nil {
		l.session = make(map[string]map[string]string)
	}
	if l.session[srv] == nil {
		l.session[srv] = make(map[string]string)
	}

	pinnedServerTools, hasServerPin := l.Servers[srv]
	var violations []LockViolation
	dirty := false

	for _, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			continue
		}
		hash := ComputeToolHash(tool)

		// 1. Mid-session rug-pull detection: compare against the initial hash observed in this session.
		if prevHash, seen := l.session[srv][name]; seen && prevHash != hash {
			violations = append(violations, LockViolation{
				Server:       srv,
				ToolName:     name,
				Kind:         "mid_session_mutation",
				RuleID:       "MCP02-RUG-PULL",
				Severity:     policy.SeverityCritical,
				ExpectedHash: prevHash,
				ActualHash:   hash,
				Message:      fmt.Sprintf("tool %q mutated mid-session (expected %s, got %s)", name, shortHash(prevHash), shortHash(hash)),
			})
			continue
		}
		if _, seen := l.session[srv][name]; !seen {
			l.session[srv][name] = hash
		}

		// 2. Persisted lockfile verification.
		if normMode == "update" {
			if l.Servers[srv] == nil {
				l.Servers[srv] = make(map[string]LockedTool)
			}
			existing, ok := l.Servers[srv][name]
			if !ok || existing.SHA256 != hash {
				firstSeen := now
				if ok && !existing.FirstSeen.IsZero() {
					firstSeen = existing.FirstSeen
				}
				l.Servers[srv][name] = LockedTool{
					Name:        name,
					SHA256:      hash,
					Description: truncateEvidence(tool.Description, 160),
					FirstSeen:   firstSeen,
					UpdatedAt:   now,
				}
				dirty = true
			}
			continue
		}

		if hasServerPin {
			locked, ok := pinnedServerTools[name]
			if !ok {
				violations = append(violations, LockViolation{
					Server:     srv,
					ToolName:   name,
					Kind:       "unpinned_tool",
					RuleID:     "MCP02-UNPINNED-TOOL",
					Severity:   policy.SeverityHigh,
					ActualHash: hash,
					Message:    fmt.Sprintf("tool %q is not pinned in lockfile for server %q", name, srv),
				})
			} else if locked.SHA256 != hash {
				violations = append(violations, LockViolation{
					Server:       srv,
					ToolName:     name,
					Kind:         "hash_mismatch",
					RuleID:       "MCP02-RUG-PULL",
					Severity:     policy.SeverityCritical,
					ExpectedHash: locked.SHA256,
					ActualHash:   hash,
					Message:      fmt.Sprintf("tool %q schema hash mismatch against lockfile (expected %s, got %s)", name, shortHash(locked.SHA256), shortHash(hash)),
				})
			}
		}
	}

	savePath := l.path
	l.mu.Unlock()

	if dirty && strings.TrimSpace(savePath) != "" {
		_ = l.Save()
	}

	return violations
}

func normalizeServerKey(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return "default"
	}
	return s
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
