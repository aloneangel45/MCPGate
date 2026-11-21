package preset

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// IDEConfig describes a supported IDE's MCP configuration file location and schema.
type IDEConfig struct {
	ID        string `json:"id"`         // claude | claude-code | cursor | vscode | windsurf | zed
	Name      string `json:"name"`       // Human-readable IDE name
	Path      string `json:"path"`       // Resolved filesystem path to config file
	ServerKey string `json:"server_key"` // Root JSON object key holding MCP servers
	Exists    bool   `json:"exists"`     // Whether the config file currently exists on disk
}

// WrapOptions controls how MCPGate wraps an IDE's MCP configuration file.
type WrapOptions struct {
	// BinaryPath is the executable path or name invoked by the IDE (default: "mcpgate").
	BinaryPath string
	// Preset is the MCPGate policy preset passed via --preset (default: "balanced").
	Preset string
	// PolicyPath optionally passes --policy <path> instead of --preset.
	PolicyPath string
	// ServerKey overrides the root JSON key ("mcpServers", "servers", "context_servers").
	// When empty, it is auto-detected from the document (defaulting to "mcpServers").
	ServerKey string
	// OnlyServers restricts wrapping to the listed server names when non-empty.
	OnlyServers []string
	// SkipServers skips wrapping the listed server names.
	SkipServers []string
	// SelfMCP adds/updates MCPGate's own read-only MCP server ("mcpgate": {"command": ..., "args": ["mcp"]})
	// instead of wrapping existing stdio MCP servers.
	SelfMCP bool
	// SelfName customizes the key name used in SelfMCP mode (default: "mcpgate").
	SelfName string
	// DryRun, when used with WrapFile, computes changes without writing to disk.
	DryRun bool
}

// WrapResult summarizes the outcome of WrapConfig / WrapFile.
type WrapResult struct {
	ServerKey      string   `json:"server_key"`
	Wrapped        []string `json:"wrapped,omitempty"`
	AlreadyWrapped []string `json:"already_wrapped,omitempty"`
	Skipped        []string `json:"skipped,omitempty"`
	SelfMCPAdded   bool     `json:"self_mcp_added,omitempty"`
	Changed        bool     `json:"changed"`
}

// UnwrapOptions controls reverting MCPGate-wrapped servers back to their original commands.
type UnwrapOptions struct {
	// ServerKey overrides the root JSON key; auto-detected when empty.
	ServerKey string
	// OnlyServers restricts unwrapping to the listed server names when non-empty.
	OnlyServers []string
	// RemoveSelfMCP also removes MCPGate's own self-MCP entry if present.
	RemoveSelfMCP bool
	// SelfName is the server key name for self-MCP removal (default: "mcpgate").
	SelfName string
	// DryRun, when used with UnwrapFile, computes changes without writing to disk.
	DryRun bool
}

// UnwrapResult summarizes the outcome of UnwrapConfig / UnwrapFile.
type UnwrapResult struct {
	ServerKey      string   `json:"server_key"`
	Unwrapped      []string `json:"unwrapped,omitempty"`
	NotWrapped     []string `json:"not_wrapped,omitempty"`
	SelfMCPRemoved bool     `json:"self_mcp_removed,omitempty"`
	Changed        bool     `json:"changed"`
}

var supportedIDEOrder = []string{
	"claude",
	"claude-code",
	"cursor",
	"vscode",
	"windsurf",
	"zed",
}

// SupportedIDEs returns the canonical list of supported IDE identifiers.
func SupportedIDEs() []string {
	out := make([]string, len(supportedIDEOrder))
	copy(out, supportedIDEOrder)
	return out
}

// ResolveIDEConfig resolves the MCP config path and schema for a single IDE on the current OS.
func ResolveIDEConfig(ide string) (IDEConfig, error) {
	return ResolveIDEConfigFor(ide, runtime.GOOS, os.Getenv)
}

// ResolveIDEConfigFor resolves an IDE's MCP config path using an explicit OS and env lookup
// (enabling deterministic cross-platform and hermetic testing).
func ResolveIDEConfigFor(ide, goos string, getenv func(string) string) (IDEConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	id := normalizeIDE(ide)
	home := resolveHome(goos, getenv)
	appData := resolveAppData(goos, home, getenv)
	xdgConfig := resolveXDGConfig(goos, home, getenv)

	var cfg IDEConfig
	switch id {
	case "claude":
		cfg = IDEConfig{
			ID:        "claude",
			Name:      "Claude Desktop",
			ServerKey: "mcpServers",
		}
		switch goos {
		case "windows":
			cfg.Path = joinForOS(goos, appData, "Claude", "claude_desktop_config.json")
		case "darwin":
			cfg.Path = joinForOS(goos, home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
		default:
			cfg.Path = joinForOS(goos, xdgConfig, "Claude", "claude_desktop_config.json")
		}

	case "claude-code":
		cfg = IDEConfig{
			ID:        "claude-code",
			Name:      "Claude Code",
			ServerKey: "mcpServers",
			Path:      joinForOS(goos, home, ".claude.json"),
		}

	case "cursor":
		cfg = IDEConfig{
			ID:        "cursor",
			Name:      "Cursor",
			ServerKey: "mcpServers",
			Path:      joinForOS(goos, home, ".cursor", "mcp.json"),
		}

	case "vscode":
		cfg = IDEConfig{
			ID:        "vscode",
			Name:      "VS Code",
			ServerKey: "servers",
		}
		switch goos {
		case "windows":
			cfg.Path = joinForOS(goos, appData, "Code", "User", "mcp.json")
		case "darwin":
			cfg.Path = joinForOS(goos, home, "Library", "Application Support", "Code", "User", "mcp.json")
		default:
			cfg.Path = joinForOS(goos, xdgConfig, "Code", "User", "mcp.json")
		}

	case "windsurf":
		cfg = IDEConfig{
			ID:        "windsurf",
			Name:      "Windsurf",
			ServerKey: "mcpServers",
			Path:      joinForOS(goos, home, ".codeium", "windsurf", "mcp_config.json"),
		}

	case "zed":
		cfg = IDEConfig{
			ID:        "zed",
			Name:      "Zed",
			ServerKey: "context_servers",
		}
		switch goos {
		case "windows":
			cfg.Path = joinForOS(goos, appData, "Zed", "settings.json")
		default:
			cfg.Path = joinForOS(goos, xdgConfig, "zed", "settings.json")
		}

	default:
		return IDEConfig{}, fmt.Errorf("unsupported IDE %q (supported: %s)", ide, strings.Join(supportedIDEOrder, ", "))
	}

	if cfg.Path != "" {
		if info, err := os.Stat(cfg.Path); err == nil && !info.IsDir() {
			cfg.Exists = true
		}
	}
	return cfg, nil
}

// AllIDEConfigs returns all known IDE MCP config targets with their Exists status populated.
func AllIDEConfigs() []IDEConfig {
	return AllIDEConfigsFor(runtime.GOOS, os.Getenv)
}

// AllIDEConfigsFor returns all known IDE MCP config targets for a specific OS and env lookup.
func AllIDEConfigsFor(goos string, getenv func(string) string) []IDEConfig {
	out := make([]IDEConfig, 0, len(supportedIDEOrder))
	for _, id := range supportedIDEOrder {
		if cfg, err := ResolveIDEConfigFor(id, goos, getenv); err == nil {
			out = append(out, cfg)
		}
	}
	return out
}

// DiscoverIDEConfigs returns all existing IDE MCP configuration files found on the host.
func DiscoverIDEConfigs() []IDEConfig {
	return DiscoverIDEConfigsFor(runtime.GOOS, os.Getenv)
}

// DiscoverIDEConfigsFor returns existing IDE MCP configuration files for a specific OS and env lookup.
func DiscoverIDEConfigsFor(goos string, getenv func(string) string) []IDEConfig {
	all := AllIDEConfigsFor(goos, getenv)
	found := make([]IDEConfig, 0, len(all))
	for _, cfg := range all {
		if cfg.Exists {
			found = append(found, cfg)
		}
	}
	return found
}

// StripJSONC strips single-line (//), block (/* */), and trailing commas from JSONC input,
// preserving string literals and newline counts for accurate line reporting.
func StripJSONC(input []byte) []byte {
	noComments := stripComments(input)
	return stripTrailingCommas(noComments)
}

func stripComments(src []byte) []byte {
	out := make([]byte, 0, len(src))
	inString := false
	escaped := false

	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}

		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}

		if c == '/' && i+1 < len(src) {
			next := src[i+1]
			if next == '/' {
				// Single-line comment: skip until newline, keep newline.
				i += 2
				for i < len(src) && src[i] != '\n' {
					i++
				}
				if i < len(src) && src[i] == '\n' {
					out = append(out, '\n')
				}
				continue
			}
			if next == '*' {
				// Block comment: preserve newlines inside block comment.
				i += 2
				for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
					if src[i] == '\n' {
						out = append(out, '\n')
					}
					i++
				}
				i++ // skip closing '/'
				continue
			}
		}

		out = append(out, c)
	}
	return out
}

func stripTrailingCommas(src []byte) []byte {
	out := make([]byte, 0, len(src))
	inString := false
	escaped := false

	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}

		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}

		if c == ',' {
			j := i + 1
			for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r' || src[j] == '\n') {
				j++
			}
			if j < len(src) && (src[j] == '}' || src[j] == ']') {
				// Drop trailing comma.
				continue
			}
		}

		out = append(out, c)
	}
	return out
}

// WrapConfig parses an IDE MCP config (JSON or JSONC) and either wraps all eligible stdio
// MCP servers with MCPGate (idempotently) or installs MCPGate's own self-MCP server entry.
// All unrelated top-level JSON keys and server fields (env, disabled, etc.) are preserved.
func WrapConfig(rawJSON []byte, opts WrapOptions) ([]byte, WrapResult, error) {
	bin := strings.TrimSpace(opts.BinaryPath)
	if bin == "" {
		bin = "mcpgate"
	}
	presetName := strings.TrimSpace(opts.Preset)
	if presetName == "" {
		presetName = "balanced"
	}
	selfName := strings.TrimSpace(opts.SelfName)
	if selfName == "" {
		selfName = "mcpgate"
	}

	root, err := parseRootObject(rawJSON)
	if err != nil {
		return nil, WrapResult{}, err
	}

	serverKey := detectServerKey(root, opts.ServerKey)
	res := WrapResult{ServerKey: serverKey}

	servers, err := decodeServersMap(root, serverKey)
	if err != nil {
		return nil, WrapResult{}, err
	}

	if opts.SelfMCP {
		changed := upsertSelfMCP(servers, serverKey, selfName, bin)
		res.SelfMCPAdded = changed
		if !changed {
			res.AlreadyWrapped = append(res.AlreadyWrapped, selfName)
		}
		res.Changed = changed
	} else {
		onlySet := toSet(opts.OnlyServers)
		skipSet := toSet(opts.SkipServers)

		names := sortedKeys(servers)
		for _, name := range names {
			if len(onlySet) > 0 && !onlySet[name] {
				res.Skipped = append(res.Skipped, name)
				continue
			}
			if skipSet[name] {
				res.Skipped = append(res.Skipped, name)
				continue
			}

			srvObj, ok := servers[name].(map[string]any)
			if !ok {
				res.Skipped = append(res.Skipped, name)
				continue
			}

			status, modified := wrapServerEntry(srvObj, serverKey, bin, presetName, opts.PolicyPath)
			switch status {
			case "wrapped":
				res.Wrapped = append(res.Wrapped, name)
				if modified {
					res.Changed = true
				}
			case "already":
				res.AlreadyWrapped = append(res.AlreadyWrapped, name)
			default:
				res.Skipped = append(res.Skipped, name)
			}
		}
	}

	// Re-encode servers map back into root, preserving all unrelated top-level keys verbatim.
	encodedServers, err := json.Marshal(servers)
	if err != nil {
		return nil, WrapResult{}, fmt.Errorf("marshal %s: %w", serverKey, err)
	}
	root[serverKey] = json.RawMessage(encodedServers)

	out, err := marshalRootObject(root)
	if err != nil {
		return nil, WrapResult{}, err
	}
	return out, res, nil
}

// UnwrapConfig reverts MCPGate-wrapped stdio MCP servers back to their original command and args,
// preserving all unrelated top-level JSON keys and per-server properties.
func UnwrapConfig(rawJSON []byte, opts UnwrapOptions) ([]byte, UnwrapResult, error) {
	selfName := strings.TrimSpace(opts.SelfName)
	if selfName == "" {
		selfName = "mcpgate"
	}

	root, err := parseRootObject(rawJSON)
	if err != nil {
		return nil, UnwrapResult{}, err
	}

	serverKey := detectServerKey(root, opts.ServerKey)
	res := UnwrapResult{ServerKey: serverKey}

	if _, exists := root[serverKey]; !exists {
		out, err := marshalRootObject(root)
		return out, res, err
	}

	servers, err := decodeServersMap(root, serverKey)
	if err != nil {
		return nil, UnwrapResult{}, err
	}

	onlySet := toSet(opts.OnlyServers)
	names := sortedKeys(servers)

	for _, name := range names {
		if len(onlySet) > 0 && !onlySet[name] {
			continue
		}
		srvObj, ok := servers[name].(map[string]any)
		if !ok {
			continue
		}

		if opts.RemoveSelfMCP && name == selfName && isSelfMCPEntry(srvObj, serverKey) {
			delete(servers, name)
			res.SelfMCPRemoved = true
			res.Changed = true
			continue
		}

		if unwrapServerEntry(srvObj, serverKey) {
			res.Unwrapped = append(res.Unwrapped, name)
			res.Changed = true
		} else {
			res.NotWrapped = append(res.NotWrapped, name)
		}
	}

	encodedServers, err := json.Marshal(servers)
	if err != nil {
		return nil, UnwrapResult{}, fmt.Errorf("marshal %s: %w", serverKey, err)
	}
	root[serverKey] = json.RawMessage(encodedServers)

	out, err := marshalRootObject(root)
	if err != nil {
		return nil, UnwrapResult{}, err
	}
	return out, res, nil
}

// WrapFile reads an IDE MCP config file, applies WrapConfig, and atomically writes the result.
// If the file does not exist and SelfMCP is enabled, a new config file is created.
func WrapFile(path string, opts WrapOptions) (WrapResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && opts.SelfMCP {
			raw = []byte("{}\n")
		} else {
			return WrapResult{}, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	updated, res, err := WrapConfig(raw, opts)
	if err != nil {
		return WrapResult{}, err
	}
	if opts.DryRun || (!res.Changed && fileExists(path)) {
		return res, nil
	}
	if err := WriteFileAtomic(path, updated, 0600); err != nil {
		return WrapResult{}, err
	}
	return res, nil
}

// UnwrapFile reads an IDE MCP config file, applies UnwrapConfig, and atomically writes the result.
func UnwrapFile(path string, opts UnwrapOptions) (UnwrapResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return UnwrapResult{}, fmt.Errorf("read config %q: %w", path, err)
	}

	updated, res, err := UnwrapConfig(raw, opts)
	if err != nil {
		return UnwrapResult{}, err
	}
	if opts.DryRun || !res.Changed {
		return res, nil
	}
	if err := WriteFileAtomic(path, updated, 0600); err != nil {
		return UnwrapResult{}, err
	}
	return res, nil
}

// WriteFileAtomic writes data to a temporary file in the target directory and atomically
// renames it into place so partial writes can never corrupt an IDE config file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if perm == 0 {
		perm = 0600
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create parent dir %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".mcpgate-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
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
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		// Best-effort on filesystems that ignore POSIX chmod bits.
		_ = err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomic rename to %q: %w", path, err)
	}
	cleanup = false
	return nil
}

// IsMCPGateCommand reports whether a command executable refers to MCPGate.
func IsMCPGateCommand(cmd string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(cmd)))
	base = strings.TrimSuffix(base, ".exe")
	return base == "mcpgate"
}

// ExtractWrappedCommand detects an MCPGate-wrapped stdio invocation
// (e.g. `mcpgate run --preset balanced -- npx ...`) and returns the underlying command and args.
func ExtractWrappedCommand(cmd string, args []string) (origCmd string, origArgs []string, wrapped bool) {
	if !IsMCPGateCommand(cmd) || len(args) < 3 {
		return "", nil, false
	}
	if strings.ToLower(strings.TrimSpace(args[0])) != "run" {
		return "", nil, false
	}
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			if i+1 >= len(args) {
				return "", nil, false
			}
			origCmd = args[i+1]
			if i+2 < len(args) {
				origArgs = append([]string(nil), args[i+2:]...)
			}
			return origCmd, origArgs, true
		}
	}
	return "", nil, false
}

func wrapServerEntry(srv map[string]any, serverKey, bin, presetName, policyPath string) (string, bool) {
	// Zed nested command object format: {"command": {"path": "...", "args": [...]}}
	if serverKey == "context_servers" {
		if cmdMap, ok := srv["command"].(map[string]any); ok {
			cmdPath, _ := cmdMap["path"].(string)
			cmdPath = strings.TrimSpace(cmdPath)
			if cmdPath == "" {
				return "skipped", false
			}
			args := toStringSlice(cmdMap["args"])
			if isAlreadyWrapped(cmdPath, args) {
				return "already", false
			}
			newArgs := buildWrapArgs(presetName, policyPath, cmdPath, args)
			cmdMap["path"] = bin
			cmdMap["args"] = toAnySlice(newArgs)
			return "wrapped", true
		}
	}

	cmd, ok := srv["command"].(string)
	cmd = strings.TrimSpace(cmd)
	if !ok || cmd == "" {
		// Remote HTTP/SSE server or non-stdio entry.
		return "skipped", false
	}
	args := toStringSlice(srv["args"])
	if isAlreadyWrapped(cmd, args) {
		return "already", false
	}

	newArgs := buildWrapArgs(presetName, policyPath, cmd, args)
	srv["command"] = bin
	srv["args"] = toAnySlice(newArgs)
	return "wrapped", true
}

func unwrapServerEntry(srv map[string]any, serverKey string) bool {
	if serverKey == "context_servers" {
		if cmdMap, ok := srv["command"].(map[string]any); ok {
			cmdPath, _ := cmdMap["path"].(string)
			args := toStringSlice(cmdMap["args"])
			origCmd, origArgs, wrapped := ExtractWrappedCommand(cmdPath, args)
			if !wrapped {
				return false
			}
			cmdMap["path"] = origCmd
			if len(origArgs) > 0 {
				cmdMap["args"] = toAnySlice(origArgs)
			} else {
				delete(cmdMap, "args")
			}
			return true
		}
	}

	cmd, ok := srv["command"].(string)
	if !ok || strings.TrimSpace(cmd) == "" {
		return false
	}
	args := toStringSlice(srv["args"])
	origCmd, origArgs, wrapped := ExtractWrappedCommand(cmd, args)
	if !wrapped {
		return false
	}
	srv["command"] = origCmd
	if len(origArgs) > 0 {
		srv["args"] = toAnySlice(origArgs)
	} else {
		delete(srv, "args")
	}
	return true
}

func upsertSelfMCP(servers map[string]any, serverKey, selfName, bin string) bool {
	if existing, ok := servers[selfName].(map[string]any); ok {
		if isSelfMCPEntryWithBin(existing, serverKey, bin) {
			return false
		}
	}
	if serverKey == "context_servers" {
		servers[selfName] = map[string]any{
			"command": map[string]any{
				"path": bin,
				"args": []any{"mcp"},
			},
		}
	} else {
		servers[selfName] = map[string]any{
			"command": bin,
			"args":    []any{"mcp"},
		}
	}
	return true
}

func isSelfMCPEntry(srv map[string]any, serverKey string) bool {
	cmd, args := extractCmdAndArgs(srv, serverKey)
	return IsMCPGateCommand(cmd) && len(args) >= 1 && strings.EqualFold(args[0], "mcp")
}

func isSelfMCPEntryWithBin(srv map[string]any, serverKey, bin string) bool {
	cmd, args := extractCmdAndArgs(srv, serverKey)
	return cmd == bin && len(args) == 1 && args[0] == "mcp"
}

func extractCmdAndArgs(srv map[string]any, serverKey string) (string, []string) {
	if serverKey == "context_servers" {
		if cmdMap, ok := srv["command"].(map[string]any); ok {
			p, _ := cmdMap["path"].(string)
			return strings.TrimSpace(p), toStringSlice(cmdMap["args"])
		}
	}
	c, _ := srv["command"].(string)
	return strings.TrimSpace(c), toStringSlice(srv["args"])
}

func isAlreadyWrapped(cmd string, args []string) bool {
	if !IsMCPGateCommand(cmd) {
		return false
	}
	if len(args) >= 1 && strings.EqualFold(args[0], "mcp") {
		return true
	}
	_, _, wrapped := ExtractWrappedCommand(cmd, args)
	return wrapped
}

func buildWrapArgs(presetName, policyPath, origCmd string, origArgs []string) []string {
	out := []string{"run"}
	if strings.TrimSpace(policyPath) != "" {
		out = append(out, "--policy", strings.TrimSpace(policyPath))
	} else {
		out = append(out, "--preset", presetName)
	}
	out = append(out, "--", origCmd)
	out = append(out, origArgs...)
	return out
}

func parseRootObject(rawJSON []byte) (map[string]json.RawMessage, error) {
	cleaned := bytes.TrimSpace(StripJSONC(rawJSON))
	if len(cleaned) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &root); err != nil {
		return nil, fmt.Errorf("parse MCP config JSON: %w", err)
	}
	if root == nil {
		root = map[string]json.RawMessage{}
	}
	return root, nil
}

func marshalRootObject(root map[string]json.RawMessage) ([]byte, error) {
	buf, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal MCP config JSON: %w", err)
	}
	return append(buf, '\n'), nil
}

func detectServerKey(root map[string]json.RawMessage, override string) string {
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}
	for _, candidate := range []string{"mcpServers", "servers", "context_servers"} {
		if _, ok := root[candidate]; ok {
			return candidate
		}
	}
	return "mcpServers"
}

func decodeServersMap(root map[string]json.RawMessage, serverKey string) (map[string]any, error) {
	raw, exists := root[serverKey]
	if !exists || len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return map[string]any{}, nil
	}
	var servers map[string]any
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil, fmt.Errorf("decode %q object: %w", serverKey, err)
	}
	if servers == nil {
		servers = map[string]any{}
	}
	return servers, nil
}

func normalizeIDE(ide string) string {
	switch strings.ToLower(strings.TrimSpace(ide)) {
	case "claude", "claude-desktop", "claudedesktop":
		return "claude"
	case "claude-code", "claudecode":
		return "claude-code"
	case "cursor":
		return "cursor"
	case "vscode", "vs-code", "code":
		return "vscode"
	case "windsurf":
		return "windsurf"
	case "zed":
		return "zed"
	default:
		return strings.ToLower(strings.TrimSpace(ide))
	}
}

func resolveHome(goos string, getenv func(string) string) string {
	if goos == "windows" {
		if v := strings.TrimSpace(getenv("USERPROFILE")); v != "" {
			return v
		}
		if v := strings.TrimSpace(getenv("HOME")); v != "" {
			return v
		}
	} else {
		if v := strings.TrimSpace(getenv("HOME")); v != "" {
			return v
		}
		if v := strings.TrimSpace(getenv("USERPROFILE")); v != "" {
			return v
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

func resolveAppData(goos, home string, getenv func(string) string) string {
	if v := strings.TrimSpace(getenv("APPDATA")); v != "" {
		return v
	}
	if home != "" {
		return joinForOS(goos, home, "AppData", "Roaming")
	}
	return ""
}

func resolveXDGConfig(goos, home string, getenv func(string) string) string {
	if v := strings.TrimSpace(getenv("XDG_CONFIG_HOME")); v != "" {
		return v
	}
	if home != "" {
		return joinForOS(goos, home, ".config")
	}
	return ""
}

func joinForOS(goos string, elems ...string) string {
	filtered := make([]string, 0, len(elems))
	for _, e := range elems {
		e = strings.TrimSpace(e)
		if e != "" {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		return ""
	}
	if goos == runtime.GOOS {
		return filepath.Join(filtered...)
	}
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	for i, e := range filtered {
		if i == 0 {
			filtered[i] = strings.TrimRight(e, `/\`)
		} else {
			filtered[i] = strings.Trim(e, `/\`)
		}
	}
	return strings.Join(filtered, sep)
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return append([]string(nil), s...)
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" {
			m[it] = true
		}
	}
	return m
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
