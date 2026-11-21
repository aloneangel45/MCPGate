package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// TestSandboxHelperProcess is invoked as a child subprocess by sandbox tests.
func TestSandboxHelperProcess(t *testing.T) {
	mode := os.Getenv("MCPGATE_SANDBOX_HELPER_MODE")
	if mode == "" {
		return
	}
	switch mode {
	case "dump_env":
		wd, _ := os.Getwd()
		payload := map[string]any{
			"wd":  wd,
			"env": os.Environ(),
		}
		_ = json.NewEncoder(os.Stdout).Encode(payload)
		os.Exit(0)
	case "sleep":
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestCapabilities(t *testing.T) {
	caps := Capabilities()
	if caps.OS != runtime.GOOS {
		t.Fatalf("expected OS %q, got %q", runtime.GOOS, caps.OS)
	}
	if caps.Arch != runtime.GOARCH {
		t.Fatalf("expected Arch %q, got %q", runtime.GOARCH, caps.Arch)
	}
	if !caps.CleanEnvSupported {
		t.Fatalf("expected CleanEnvSupported=true")
	}
	if caps.ProcessIsolation == "" {
		t.Fatalf("expected non-empty ProcessIsolation")
	}
	if caps.FilesystemJail == "" {
		t.Fatalf("expected non-empty FilesystemJail")
	}
	if len(caps.Details) == 0 {
		t.Fatalf("expected diagnostic Details")
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(caps.ProcessIsolation, "Job Object") {
			t.Fatalf("expected Win32 Job Object process isolation on Windows, got %q", caps.ProcessIsolation)
		}
		if !caps.MemoryLimitSupported {
			t.Fatalf("expected MemoryLimitSupported=true on Windows")
		}
	}
}

func TestBuildCleanEnvStripsHostSecrets(t *testing.T) {
	baseEnv := []string{
		"PATH=/usr/bin:/bin",
		"TEMP=/tmp",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234",
		"OPENAI_API_KEY=sk-proj-secret-openai-key",
		"ANTHROPIC_API_KEY=sk-ant-api03-secret",
	}

	cfg := policy.SandboxPolicy{
		CleanEnv: true,
		PassEnv:  []string{"PATH", "temp"}, // lowercase "temp" verifies case-insensitive match on Windows
	}
	extra := map[string]string{
		"HTTP_PROXY":  "http://127.0.0.1:8899",
		"HTTPS_PROXY": "http://127.0.0.1:8899",
	}

	gotWin := buildCleanEnvForOS(cfg, baseEnv, extra, true)
	envMap := envSliceToMap(gotWin)

	for _, forbidden := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"} {
		if _, exists := envMap[forbidden]; exists {
			t.Fatalf("CleanEnv leaked forbidden host secret %q", forbidden)
		}
	}
	if envMap["PATH"] != "/usr/bin:/bin" {
		t.Fatalf("expected PATH forwarded, got %q", envMap["PATH"])
	}
	if envMap["TEMP"] != "/tmp" {
		t.Fatalf("expected case-insensitive TEMP forwarded on Windows, got %v", envMap)
	}
	if envMap["HTTP_PROXY"] != "http://127.0.0.1:8899" || envMap["HTTPS_PROXY"] != "http://127.0.0.1:8899" {
		t.Fatalf("expected extra proxy vars injected, got %v", envMap)
	}

	// On Unix (case-sensitive), "temp" should not match "TEMP".
	gotUnix := buildCleanEnvForOS(cfg, baseEnv, extra, false)
	unixMap := envSliceToMap(gotUnix)
	if _, ok := unixMap["TEMP"]; ok {
		t.Fatalf("expected case-sensitive matching on Unix")
	}

	// CleanEnv: false preserves base env and overrides with extra.
	cfgNoClean := policy.SandboxPolicy{CleanEnv: false}
	gotAll := BuildCleanEnv(cfgNoClean, baseEnv, map[string]string{"HTTP_PROXY": "http://127.0.0.1:9000"})
	allMap := envSliceToMap(gotAll)
	if allMap["OPENAI_API_KEY"] != "sk-proj-secret-openai-key" {
		t.Fatalf("expected base env retained when CleanEnv=false")
	}
	if allMap["HTTP_PROXY"] != "http://127.0.0.1:9000" {
		t.Fatalf("expected extra env merged when CleanEnv=false")
	}
}

func TestGenerateSeatbeltProfile(t *testing.T) {
	prof := GenerateSeatbeltProfile("/workspace/project", true)
	for _, want := range []string{
		"(version 1)",
		"(deny file-read*",
		"\\.ssh",
		"\\.aws",
		"(deny file-write*)",
		"(allow file-write* (subpath \"",
	} {
		if !strings.Contains(prof, want) {
			t.Fatalf("seatbelt profile missing %q:\n%s", want, prof)
		}
	}
}

func TestPrepareCommandCleanEnvAndWorkDir(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "super-secret-aws-value")
	t.Setenv("OPENAI_API_KEY", "sk-live-secret-openai")

	tmpDir := t.TempDir()
	cfg := policy.SandboxPolicy{
		CleanEnv:     true,
		PassEnv:      []string{"PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "HOME"},
		WorkDir:      tmpDir,
		MaxMemoryMB:  512,
		MaxProcesses: 16,
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	extra := map[string]string{
		"MCPGATE_SANDBOX_HELPER_MODE": "dump_env",
		"HTTP_PROXY":                  "http://127.0.0.1:18080",
	}

	wc, err := PrepareCommand(context.Background(), cfg, exe, []string{"-test.run=TestSandboxHelperProcess"}, extra)
	if err != nil {
		t.Fatalf("PrepareCommand: %v", err)
	}
	defer func() { _ = wc.Cleanup() }()

	var stdout, stderr bytes.Buffer
	wc.Cmd.Stdout = &stdout
	wc.Cmd.Stderr = &stderr

	if err := wc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := wc.Wait(); err != nil {
		t.Fatalf("Wait: %v (stderr: %s)", err, stderr.String())
	}

	var result struct {
		WD  string   `json:"wd"`
		Env []string `json:"env"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode helper output: %v (raw: %q)", err, stdout.String())
	}

	childEnv := envSliceToMap(result.Env)
	if _, leaked := childEnv["AWS_SECRET_ACCESS_KEY"]; leaked {
		t.Fatalf("child process inherited AWS_SECRET_ACCESS_KEY despite CleanEnv=true")
	}
	if _, leaked := childEnv["OPENAI_API_KEY"]; leaked {
		t.Fatalf("child process inherited OPENAI_API_KEY despite CleanEnv=true")
	}
	if childEnv["HTTP_PROXY"] != "http://127.0.0.1:18080" {
		t.Fatalf("child process missing injected HTTP_PROXY: %v", childEnv)
	}

	wantWD, _ := filepath.EvalSymlinks(tmpDir)
	gotWD, _ := filepath.EvalSymlinks(result.WD)
	if !strings.EqualFold(filepath.Clean(wantWD), filepath.Clean(gotWD)) {
		t.Fatalf("expected child WorkDir %q, got %q", wantWD, gotWD)
	}
}

func TestPrepareCommandProcessCleanup(t *testing.T) {
	cfg := policy.SandboxPolicy{
		CleanEnv:     true,
		PassEnv:      []string{"PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "HOME"},
		MaxMemoryMB:  512,
		MaxProcesses: 16,
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	wc, err := PrepareCommand(context.Background(), cfg, exe, []string{"-test.run=TestSandboxHelperProcess"}, map[string]string{
		"MCPGATE_SANDBOX_HELPER_MODE": "sleep",
	})
	if err != nil {
		t.Fatalf("PrepareCommand: %v", err)
	}

	stdoutPipe, err := wc.Cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	if err := wc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait until child prints "ready\n" so we know it is actively running and assigned to Job Object / PGID.
	buf := make([]byte, 6)
	readDone := make(chan error, 1)
	go func() {
		_, rerr := stdoutPipe.Read(buf)
		readDone <- rerr
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("reading ready signal from child: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = wc.Kill()
		_ = wc.Cleanup()
		t.Fatalf("timed out waiting for child process to start")
	}

	// Cleanup / Kill must terminate the child process immediately (Win32 Job Object / POSIX PGID).
	if err := wc.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	// Idempotent second Cleanup must succeed without error.
	if err := wc.Cleanup(); err != nil {
		t.Fatalf("second Cleanup should be idempotent: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- wc.Wait()
	}()
	select {
	case <-waitDone:
		// Process terminated cleanly after Job Object close / PGID kill!
	case <-time.After(5 * time.Second):
		_ = wc.Kill()
		t.Fatalf("child process did not terminate promptly after sandbox Cleanup()")
	}
}

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if idx := strings.IndexByte(kv, '='); idx > 0 {
			m[kv[:idx]] = kv[idx+1:]
		}
	}
	return m
}
