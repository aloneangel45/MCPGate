package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// HostCapabilities describes the OS-level isolation primitives available on the current host.
type HostCapabilities struct {
	OS                   string   `json:"os"`
	Arch                 string   `json:"arch"`
	ProcessIsolation     string   `json:"process_isolation"`
	CleanEnvSupported    bool     `json:"clean_env_supported"`
	FilesystemJail       string   `json:"filesystem_jail"`
	MemoryLimitSupported bool     `json:"memory_limit_supported"`
	Details              []string `json:"details,omitempty"`
}

// WrappedCmd holds a sandbox-configured child command and its OS-specific isolation lifecycle hooks.
type WrappedCmd struct {
	Cmd            *exec.Cmd
	Cfg            policy.SandboxPolicy
	ActiveControls []string

	cancel    context.CancelFunc
	onStart   func() error
	onKill    func() error
	onCleanup func() error
	tempFiles []string

	mu      sync.Mutex
	started bool
	cleaned bool
}

// Capabilities probes the current host for supported OS sandboxing features.
// It is read-only and safe to call from diagnostics such as `mcpgate doctor`.
func Capabilities() HostCapabilities {
	return platformCapabilities()
}

// BuildCleanEnv constructs the child process environment according to SandboxPolicy.
// When cfg.CleanEnv is true, all host variables (including credentials such as AWS_*,
// GITHUB_TOKEN, OPENAI_API_KEY, ANTHROPIC_API_KEY) are stripped except keys listed in
// cfg.PassEnv (matched case-insensitively on Windows), plus all entries in extra.
func BuildCleanEnv(cfg policy.SandboxPolicy, baseEnv []string, extra map[string]string) []string {
	return buildCleanEnvForOS(cfg, baseEnv, extra, runtime.GOOS == "windows")
}

func buildCleanEnvForOS(cfg policy.SandboxPolicy, baseEnv []string, extra map[string]string, caseInsensitive bool) []string {
	normKey := func(k string) string {
		if caseInsensitive {
			return strings.ToUpper(k)
		}
		return k
	}

	result := make(map[string]string)
	origKey := make(map[string]string)

	if cfg.CleanEnv {
		allowed := make(map[string]struct{}, len(cfg.PassEnv))
		for _, k := range cfg.PassEnv {
			trimmed := strings.TrimSpace(k)
			if trimmed != "" {
				allowed[normKey(trimmed)] = struct{}{}
			}
		}
		for _, kv := range baseEnv {
			idx := strings.IndexByte(kv, '=')
			if idx <= 0 {
				continue
			}
			k := kv[:idx]
			v := kv[idx+1:]
			nk := normKey(k)
			if _, ok := allowed[nk]; ok {
				origKey[nk] = k
				result[nk] = v
			}
		}
	} else {
		for _, kv := range baseEnv {
			idx := strings.IndexByte(kv, '=')
			if idx <= 0 {
				continue
			}
			k := kv[:idx]
			v := kv[idx+1:]
			nk := normKey(k)
			origKey[nk] = k
			result[nk] = v
		}
	}

	// Sort extra keys deterministically; on case-insensitive platforms (Windows),
	// process lowercase keys before uppercase so canonical uppercase keys (e.g. HTTP_PROXY
	// over http_proxy) deterministically win deduplication.
	extraKeys := make([]string, 0, len(extra))
	for k := range extra {
		extraKeys = append(extraKeys, k)
	}
	sort.Slice(extraKeys, func(i, j int) bool {
		if caseInsensitive {
			ui, uj := strings.ToUpper(extraKeys[i]), strings.ToUpper(extraKeys[j])
			if ui == uj {
				// Lowercase sorts before uppercase so uppercase overwrites last.
				return extraKeys[i] > extraKeys[j]
			}
			return ui < uj
		}
		return extraKeys[i] < extraKeys[j]
	})

	for _, k := range extraKeys {
		trimmed := strings.TrimSpace(k)
		if trimmed == "" {
			continue
		}
		nk := normKey(trimmed)
		origKey[nk] = trimmed
		result[nk] = extra[k]
	}

	out := make([]string, 0, len(result))
	for nk, v := range result {
		out = append(out, origKey[nk]+"="+v)
	}
	sort.Strings(out)
	return out
}

// PrepareCommand creates a sandboxed WrappedCmd ready to have its stdio attached and started.
func PrepareCommand(ctx context.Context, cfg policy.SandboxPolicy, name string, args []string, extraEnv map[string]string) (*WrappedCmd, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("sandbox: command name cannot be empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	execCtx := ctx
	var cancel context.CancelFunc
	if cfg.TimeoutSeconds > 0 {
		execCtx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	}

	wc := &WrappedCmd{
		Cfg:    cfg,
		cancel: cancel,
	}

	cmdName, cmdArgs, controls, tempFiles := preparePlatformCommand(cfg, name, args)
	wc.tempFiles = append(wc.tempFiles, tempFiles...)

	cmd := exec.CommandContext(execCtx, cmdName, cmdArgs...)
	cmd.Env = BuildCleanEnv(cfg, os.Environ(), extraEnv)
	cmd.WaitDelay = 3 * time.Second

	if cfg.CleanEnv {
		wc.ActiveControls = append(wc.ActiveControls, "clean_env")
	}
	if strings.TrimSpace(cfg.WorkDir) != "" {
		cmd.Dir = cfg.WorkDir
		wc.ActiveControls = append(wc.ActiveControls, "work_dir")
	}
	wc.ActiveControls = append(wc.ActiveControls, controls...)
	wc.Cmd = cmd

	if err := configurePlatformProcess(wc); err != nil {
		_ = wc.Cleanup()
		return nil, err
	}

	return wc, nil
}

// Start launches the underlying command and activates any post-start OS containment
// (such as attaching the child process to a Win32 Job Object).
func (w *WrappedCmd) Start() error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return fmt.Errorf("sandbox: command already started")
	}
	w.started = true
	w.mu.Unlock()

	if err := w.Cmd.Start(); err != nil {
		_ = w.Cleanup()
		return err
	}

	if w.onStart != nil {
		if err := w.onStart(); err != nil {
			_ = w.Kill()
			_ = w.Cleanup()
			return err
		}
	}
	return nil
}

// Wait waits for the sandboxed command to exit.
func (w *WrappedCmd) Wait() error {
	if w.Cmd == nil {
		return nil
	}
	return w.Cmd.Wait()
}

// Kill immediately terminates the sandboxed process and any descendants in its isolation group.
func (w *WrappedCmd) Kill() error {
	w.mu.Lock()
	killFn := w.onKill
	w.mu.Unlock()

	var firstErr error
	if killFn != nil {
		if err := killFn(); err != nil {
			firstErr = err
		}
	}
	if w.Cmd != nil && w.Cmd.Process != nil {
		_ = w.Cmd.Process.Kill()
	}
	return firstErr
}

// Cleanup releases OS isolation resources (such as Win32 Job handles, process groups,
// cancel contexts, and temporary Seatbelt profiles). It is safe to call multiple times.
func (w *WrappedCmd) Cleanup() error {
	w.mu.Lock()
	if w.cleaned {
		w.mu.Unlock()
		return nil
	}
	w.cleaned = true
	cleanupFn := w.onCleanup
	cancel := w.cancel
	tempFiles := append([]string(nil), w.tempFiles...)
	w.mu.Unlock()

	var firstErr error
	if cleanupFn != nil {
		if err := cleanupFn(); err != nil {
			firstErr = err
		}
	}
	if cancel != nil {
		cancel()
	}
	for _, tf := range tempFiles {
		if tf != "" {
			_ = os.Remove(tf)
		}
	}
	return firstErr
}

// GenerateSeatbeltProfile produces a minimal macOS sandbox-exec (version 1) profile
// that blocks reads of sensitive user credential paths and optionally restricts writes
// to the configured working directory and standard temporary paths.
func GenerateSeatbeltProfile(workDir string, restrictWrites bool) string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")
	b.WriteString("(deny file-read*\n")
	b.WriteString("  (regex #\"/\\.ssh(/|$)\")\n")
	b.WriteString("  (regex #\"/\\.aws(/|$)\")\n")
	b.WriteString("  (regex #\"/\\.gnupg(/|$)\")\n")
	b.WriteString("  (regex #\"/\\.kube(/|$)\")\n")
	b.WriteString(")\n")

	if restrictWrites && strings.TrimSpace(workDir) != "" {
		b.WriteString("(deny file-write*)\n")
		// Fail closed if workDir contains raw control characters (NUL/CR/LF) that could break SBPL grammar.
		if !strings.ContainsAny(workDir, "\x00\r\n") {
			absDir, err := filepath.Abs(workDir)
			if err != nil {
				absDir = workDir
			}
			if !strings.ContainsAny(absDir, "\x00\r\n") {
				escaped := escapeSBPLString(absDir)
				b.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", escaped))
			}
		}
		b.WriteString("(allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/private/var/folders\") (literal \"/dev/null\"))\n")
	}

	return b.String()
}

func escapeSBPLString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
