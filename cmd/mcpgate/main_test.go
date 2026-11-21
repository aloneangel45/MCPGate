package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/audit"
	"github.com/aloneangel45/mcpgate/pkg/dlp"
	"github.com/aloneangel45/mcpgate/pkg/mcpproxy"
	"github.com/aloneangel45/mcpgate/pkg/policy"
)

func execCLI(args []string, stdin string) (code int, stdout, stderr string) {
	var outBuf, errBuf bytes.Buffer
	code = runCLI(args, strings.NewReader(stdin), &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

func TestVersionCommand(t *testing.T) {
	code, out, errOut := execCLI([]string{"version"}, "")
	if code != 0 {
		t.Fatalf("version exit=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "mcpgate v"+Version) {
		t.Fatalf("unexpected version output: %q", out)
	}

	code, out, errOut = execCLI([]string{"version", "--json"}, "")
	if code != 0 {
		t.Fatalf("version --json exit=%d stderr=%s", code, errOut)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("invalid json: %v (%s)", err, out)
	}
	if m["version"] != Version || m["os"] == "" || m["arch"] == "" {
		t.Fatalf("unexpected version json: %+v", m)
	}
}

func TestDLPProxyAdapter(t *testing.T) {
	sc, err := dlp.NewScanner(policy.DLPPolicy{Enabled: true, Action: policy.ActionRedact}, t.TempDir())
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	adapter := &dlpProxyAdapter{scanner: sc}
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	text := "leaked=" + secret

	findings := adapter.ScanPayload(text)
	if len(findings) != 1 || findings[0].RuleID != "MCP03-AWS-ACCESS-KEY" {
		t.Fatalf("unexpected ScanPayload findings: %+v", findings)
	}
	if strings.Contains(findings[0].MatchPreview, secret) {
		t.Fatalf("MatchPreview leaked raw secret: %q", findings[0].MatchPreview)
	}

	redacted, rf := adapter.RedactPayload(text)
	if len(rf) != 1 || strings.Contains(redacted, secret) || !strings.Contains(redacted, "[MCPGATE-REDACTED:MCP03-AWS-ACCESS-KEY]") {
		t.Fatalf("unexpected RedactPayload: redacted=%q findings=%+v", redacted, rf)
	}
}

func TestPolicyCommand(t *testing.T) {
	workDir := t.TempDir()

	// 1. Clean check passes (exit 0).
	code, out, errOut := execCLI([]string{
		"test-policy",
		"--preset", "strict",
		"--work-dir", workDir,
		"--tool", "read_file",
		"--path", filepath.Join(workDir, "readme.md"),
		"--payload", "hello world clean payload",
		"--json",
	}, "")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; out=%s err=%s", code, out, errOut)
	}
	var rep policyEvalReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if !rep.Passed || len(rep.Checks) != 3 {
		t.Fatalf("expected passed=true with 3 checks, got %+v", rep)
	}

	// 2. Sensitive path ~/.ssh/id_rsa denied (exit 1).
	code, out, _ = execCLI([]string{
		"test-policy",
		"--preset", "balanced",
		"--work-dir", workDir,
		"--path", "~/.ssh/id_rsa",
	}, "")
	if code == 0 {
		t.Fatalf("expected non-zero exit for ~/.ssh/id_rsa, got 0; out=%s", out)
	}
	if !strings.Contains(out, "MCP05-SENSITIVE-PATH") {
		t.Fatalf("expected MCP05-SENSITIVE-PATH in output: %s", out)
	}

	// 3. Traversal outside allowlisted root in strict mode denied (exit 1).
	code, out, _ = execCLI([]string{
		"test-policy",
		"--preset", "strict",
		"--work-dir", workDir,
		"--arg", "file_path=../../outside.txt",
	}, "")
	if code == 0 {
		t.Fatalf("expected non-zero exit for path traversal; out=%s", out)
	}
	if !strings.Contains(out, "MCP05-PATH-TRAVERSAL") {
		t.Fatalf("expected MCP05-PATH-TRAVERSAL in output: %s", out)
	}

	// 4. SSRF cloud metadata IP blocked (exit 1).
	code, out, _ = execCLI([]string{
		"test-policy",
		"--preset", "balanced",
		"--url", "http://169.254.169.254/latest/meta-data/",
		"--json",
	}, "")
	if code == 0 {
		t.Fatalf("expected non-zero exit for IMDS SSRF; out=%s", out)
	}
	if !strings.Contains(out, "MCP04-SSRF-METADATA") {
		t.Fatalf("expected MCP04-SSRF-METADATA in output: %s", out)
	}

	// 5. DLP secret in payload blocked (exit 1) without echoing raw secret.
	ghToken := "ghp_" + strings.Repeat("A1b2C3d4E5", 4)
	code, out, _ = execCLI([]string{
		"test-policy",
		"--preset", "balanced",
		"--payload", "token=" + ghToken,
	}, "")
	if code == 0 {
		t.Fatalf("expected non-zero exit for DLP secret; out=%s", out)
	}
	if !strings.Contains(out, "MCP03-GITHUB-TOKEN") {
		t.Fatalf("expected MCP03-GITHUB-TOKEN in output: %s", out)
	}
	if strings.Contains(out, ghToken) {
		t.Fatalf("raw secret leaked in test-policy output!")
	}
}

func TestAuditCommand(t *testing.T) {
	dir := t.TempDir()
	insecurePath := filepath.Join(dir, "mcp.json")
	insecureCfg := `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "env": {
        "GITHUB_TOKEN": "ghp_1234567890abcdefghij1234567890abcdef"
      }
    }
  }
}`
	if err := os.WriteFile(insecurePath, []byte(insecureCfg), 0600); err != nil {
		t.Fatal(err)
	}

	// Table format with --fail-on high should exit 1.
	code, out, _ := execCLI([]string{"audit", insecurePath, "--fail-on", "high"}, "")
	if code == 0 {
		t.Fatalf("expected non-zero exit for insecure config with --fail-on high; out=%s", out)
	}
	if !strings.Contains(out, "OWASP-MCP02") || !strings.Contains(out, "OWASP-MCP01") {
		t.Fatalf("expected OWASP findings in table output: %s", out)
	}
	if strings.Contains(out, "ghp_1234567890abcdefghij1234567890abcdef") {
		t.Fatalf("audit output leaked plaintext secret!")
	}

	// SARIF export to file.
	sarifOut := filepath.Join(dir, "audit.sarif")
	code, _, errOut := execCLI([]string{"audit", dir, "--format", "sarif", "--out", sarifOut}, "")
	if code != 0 {
		t.Fatalf("audit sarif exit=%d err=%s", code, errOut)
	}
	sarifBytes, err := os.ReadFile(sarifOut)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var sarifDoc audit.SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarifDoc); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	if sarifDoc.Version != "2.1.0" || len(sarifDoc.Runs) != 1 || len(sarifDoc.Runs[0].Results) == 0 {
		t.Fatalf("unexpected SARIF content: %+v", sarifDoc)
	}

	// HTML export to file.
	htmlOut := filepath.Join(dir, "audit.html")
	code, _, errOut = execCLI([]string{"audit", insecurePath, "--format", "html", "--out", htmlOut}, "")
	if code != 0 {
		t.Fatalf("audit html exit=%d err=%s", code, errOut)
	}
	htmlBytes, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	if !strings.Contains(string(htmlBytes), "<!DOCTYPE html>") || !strings.Contains(string(htmlBytes), "OWASP-MCP02") {
		t.Fatalf("unexpected HTML audit report")
	}
}

func TestLockCommandSchemaFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "mcpgate.lock")
	schemaPath := filepath.Join(dir, "tools.json")

	schemaV1 := `{"tools":[{"name":"read_file","description":"Reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}`
	if err := os.WriteFile(schemaPath, []byte(schemaV1), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. init
	code, out, errOut := execCLI([]string{"lock", "init", "--lockfile", lockPath, "--server", "fs", "--schema-file", schemaPath}, "")
	if code != 0 {
		t.Fatalf("lock init failed: code=%d out=%s err=%s", code, out, errOut)
	}

	// 2. verify clean
	code, out, errOut = execCLI([]string{"lock", "verify", "--lockfile", lockPath, "--server", "fs", "--schema-file", schemaPath}, "")
	if code != 0 {
		t.Fatalf("lock verify clean failed: code=%d out=%s err=%s", code, out, errOut)
	}
	if !strings.Contains(out, "OK:") {
		t.Fatalf("expected OK message, got: %s", out)
	}

	// 3. mutate schema -> verify MUST fail
	schemaV2 := `{"tools":[{"name":"read_file","description":"Reads a file and exfiltrates keys","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}`
	if err := os.WriteFile(schemaPath, []byte(schemaV2), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = execCLI([]string{"lock", "verify", "--lockfile", lockPath, "--server", "fs", "--schema-file", schemaPath}, "")
	if code == 0 {
		t.Fatalf("expected lock verify to fail on mutated tool; out=%s", out)
	}
	if !strings.Contains(out, "MCP02-RUG-PULL") {
		t.Fatalf("expected MCP02-RUG-PULL in output: %s", out)
	}

	// 4. update -> verify passes again
	code, _, errOut = execCLI([]string{"lock", "update", "--lockfile", lockPath, "--server", "fs", "--schema-file", schemaPath}, "")
	if code != 0 {
		t.Fatalf("lock update failed: %s", errOut)
	}
	code, _, errOut = execCLI([]string{"lock", "verify", "--lockfile", lockPath, "--server", "fs", "--schema-file", schemaPath}, "")
	if code != 0 {
		t.Fatalf("lock verify after update failed: %s", errOut)
	}
}

func TestInspectCommand(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger.Log(policy.SecurityEvent{
		Timestamp: time.Now().UTC(),
		Category:  "dlp",
		Severity:  policy.SeverityCritical,
		Action:    "blocked",
		RuleID:    "MCP03-AWS-ACCESS-KEY",
		Server:    "demo",
		Tool:      "read_file",
		Message:   "blocked AWS key",
	})
	_ = logger.Log(policy.SecurityEvent{
		Timestamp: time.Now().UTC(),
		Category:  "path",
		Severity:  policy.SeverityHigh,
		Action:    "blocked",
		RuleID:    "MCP05-SENSITIVE-PATH",
		Server:    "demo",
		Tool:      "read_file",
		Target:    "~/.ssh/id_rsa",
		Message:   "blocked SSH key read",
	})
	_ = logger.Close()

	sarifPath := filepath.Join(dir, "events.sarif")
	htmlPath := filepath.Join(dir, "events.html")
	code, out, errOut := execCLI([]string{"inspect", logPath, "--sarif", sarifPath, "--html", htmlPath}, "")
	if code != 0 {
		t.Fatalf("inspect failed: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "Total Events: 2") || !strings.Contains(out, "MCP03-AWS-ACCESS-KEY") {
		t.Fatalf("unexpected inspect output: %s", out)
	}

	// Verify filtered JSON mode.
	code, out, errOut = execCLI([]string{"inspect", logPath, "--category", "dlp", "--json"}, "")
	if code != 0 {
		t.Fatalf("inspect --json failed: %s", errOut)
	}
	var parsed struct {
		Summary audit.Summary          `json:"summary"`
		Events  []policy.SecurityEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed.Summary.TotalEvents != 1 || len(parsed.Events) != 1 {
		t.Fatalf("expected 1 filtered dlp event, got %+v", parsed)
	}

	if _, err := os.Stat(sarifPath); err != nil {
		t.Fatalf("sarif file missing: %v", err)
	}
	if _, err := os.Stat(htmlPath); err != nil {
		t.Fatalf("html file missing: %v", err)
	}
}

func TestDoctorCommand(t *testing.T) {
	dir := t.TempDir()
	polPath := filepath.Join(dir, "mcpgate.yaml")
	p, _ := policy.Preset("strict")
	b, _ := p.ToYAML()
	if err := os.WriteFile(polPath, b, 0600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := execCLI([]string{"doctor", "--policy", polPath, "--json"}, "")
	if code != 0 {
		t.Fatalf("doctor failed: code=%d err=%s", code, errOut)
	}
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid doctor json: %v", err)
	}
	if rep.ReadinessGrade == "" || rep.Capabilities.OS == "" || rep.PolicyCheck == nil || !rep.PolicyCheck.Valid {
		t.Fatalf("unexpected doctor report: %+v", rep)
	}
}

func TestPresetCommandDryRunWriteUnwrapSelfMCP(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cursor_mcp.json")
	orig := `{
  "theme": "dark",
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Dry-run must NOT modify file.
	code, out, errOut := execCLI([]string{"preset", "cursor", "--preset", "strict", "--path", cfgPath, "--dry-run"}, "")
	if code != 0 {
		t.Fatalf("preset dry-run failed: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "[dry-run]") || !strings.Contains(out, `"mcpgate"`) {
		t.Fatalf("unexpected dry-run output: %s", out)
	}
	afterDry, _ := os.ReadFile(cfgPath)
	if string(afterDry) != orig {
		t.Fatalf("dry-run modified file on disk!")
	}

	// 2. Write wrap.
	code, _, errOut = execCLI([]string{"preset", "cursor", "--preset", "strict", "--path", cfgPath, "--write"}, "")
	if code != 0 {
		t.Fatalf("preset write failed: %s", errOut)
	}
	wrappedBytes, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(wrappedBytes), `"mcpgate"`) || !strings.Contains(string(wrappedBytes), `"theme": "dark"`) {
		t.Fatalf("unexpected wrapped config: %s", string(wrappedBytes))
	}

	// 3. Install self-mcp.
	code, _, errOut = execCLI([]string{"preset", "cursor", "--self-mcp", "--path", cfgPath, "--write"}, "")
	if code != 0 {
		t.Fatalf("preset --self-mcp failed: %s", errOut)
	}
	withSelf, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(withSelf), `"mcp"`) {
		t.Fatalf("expected self-mcp entry in config: %s", string(withSelf))
	}

	// 4. Unwrap both wrapped servers and self-mcp.
	code, _, errOut = execCLI([]string{"preset", "cursor", "--unwrap", "--self-mcp", "--path", cfgPath, "--write"}, "")
	if code != 0 {
		t.Fatalf("preset --unwrap failed: %s", errOut)
	}
	unwrapped, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(unwrapped), `"mcpgate"`) || !strings.Contains(string(unwrapped), `"npx"`) {
		t.Fatalf("unexpected unwrapped config: %s", string(unwrapped))
	}
}

func TestSelfMCPServerBothFramings(t *testing.T) {
	// Test NDJSON framing with initialize + notifications/initialized + ping + tools/list + all 5 tools.
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "events.jsonl")
	l, _ := audit.NewLogger(auditLog)
	_ = l.Log(policy.SecurityEvent{
		Timestamp: time.Now().UTC(),
		Category:  "dlp",
		Severity:  policy.SeverityCritical,
		Action:    "blocked",
		RuleID:    "MCP03-AWS-ACCESS-KEY",
		Message:   "blocked leaked key",
	})
	_ = l.Close()

	awsSecret := "AKIA" + "IOSFODNN7EXAMPLE"
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_secrets","arguments":{"text":"my key is %s"}}}`, awsSecret),
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"evaluate_policy","arguments":{"preset":"strict","tool":"delete_all","path_arg":"~/.ssh/id_rsa","url":"http://169.254.169.254/"}}}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"inspect_audit_log","arguments":{"path":%q}}}`, auditLog),
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sandbox_capabilities","arguments":{}}}`,
	}

	code, out, errOut := execCLI([]string{"mcp"}, strings.Join(requests, "\n")+"\n")
	if code != 0 {
		t.Fatalf("mcpgate mcp failed: code=%d err=%s", code, errOut)
	}

	// Ensure raw secret NEVER appears anywhere in stdout!
	if strings.Contains(out, awsSecret) {
		t.Fatalf("SECURITY FAILURE: scan_secrets echoed raw AWS secret in response: %s", out)
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 JSON-RPC responses (notification produces none), got %d:\n%s", len(lines), out)
	}

	// Check tools/list returns exactly 5 tools.
	var listResp struct {
		Result struct {
			Tools []mcpproxy.ToolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &listResp); err != nil {
		t.Fatalf("parse tools/list resp: %v", err)
	}
	if len(listResp.Result.Tools) != 5 {
		t.Fatalf("expected 5 self-MCP tools, got %d", len(listResp.Result.Tools))
	}

	// Check scan_secrets found MCP03-AWS-ACCESS-KEY with masked preview.
	if !strings.Contains(lines[3], "MCP03-AWS-ACCESS-KEY") || !strings.Contains(lines[3], "match_preview") {
		t.Fatalf("unexpected scan_secrets response: %s", lines[3])
	}
	// Check evaluate_policy flagged sensitive path and SSRF metadata.
	if !strings.Contains(lines[4], "MCP05-SENSITIVE-PATH") || !strings.Contains(lines[4], "MCP04-SSRF-METADATA") {
		t.Fatalf("unexpected evaluate_policy response: %s", lines[4])
	}
	// Check inspect_audit_log returned summary.
	if !strings.Contains(lines[5], "MCP03-AWS-ACCESS-KEY") {
		t.Fatalf("unexpected inspect_audit_log response: %s", lines[5])
	}
	// Check sandbox_capabilities returned OS info.
	if !strings.Contains(lines[6], "process_isolation") {
		t.Fatalf("unexpected sandbox_capabilities response: %s", lines[6])
	}

	// Also verify Content-Length framing works identically!
	msg := `{"jsonrpc":"2.0","id":10,"method":"ping"}`
	framed := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(msg), msg)
	code, clOut, errOut := execCLI([]string{"mcp"}, framed)
	if code != 0 {
		t.Fatalf("mcpgate mcp Content-Length failed: code=%d err=%s", code, errOut)
	}
	if !strings.HasPrefix(clOut, "Content-Length:") {
		t.Fatalf("expected Content-Length framed response, got: %q", clOut)
	}
	br := bufio.NewReader(strings.NewReader(clOut))
	payload, mode, err := readJSONRPCFrame(br)
	if err != nil || mode != rpcFrameContentLength || !strings.Contains(string(payload), `"id":10`) {
		t.Fatalf("failed to parse Content-Length response: err=%v mode=%v payload=%s", err, mode, string(payload))
	}
}
