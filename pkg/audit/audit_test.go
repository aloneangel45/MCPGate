package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
	"github.com/aloneangel45/mcpgate/pkg/preset"
)

func TestLoggerConcurrentWritesAndSummary(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(logPath)
		if err != nil {
			t.Fatalf("stat audit log: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("audit log perm = %o, want 0600", perm)
		}
	}

	const workers = 12
	const perWorker = 25
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				sev := policy.SeverityHigh
				cat := "ssrf"
				act := "blocked"
				rule := "MCP06-SSRF-IMDS"
				target := "169.254.169.254"
				tool := "http_fetch"
				if i%5 == 0 {
					sev = policy.SeverityCritical
					cat = "dlp"
					act = "redacted"
					rule = "MCP03-AWS-KEY"
					target = "outbound_args"
					tool = "send_webhook"
				} else if i%3 == 0 {
					sev = policy.SeverityInfo
					cat = "tool_policy"
					act = "allowed"
					rule = "MCP07-TOOL-ALLOW"
					target = "/workspace/README.md"
					tool = "read_file"
				}
				err := logger.Log(policy.SecurityEvent{
					SessionID: fmt.Sprintf("sess-%d", id),
					Category:  cat,
					Severity:  sev,
					Action:    act,
					RuleID:    rule,
					Server:    "filesystem",
					Tool:      tool,
					Target:    target,
					Message:   fmt.Sprintf("event %d from worker %d", i, id),
				})
				if err != nil {
					t.Errorf("Log failed: %v", err)
				}
			}
		}(w)
	}
	wg.Wait()

	// Verify flush-on-write before Close() by reading the file immediately.
	eventsBeforeClose, err := LoadEvents(logPath)
	if err != nil {
		t.Fatalf("LoadEvents before close failed: %v", err)
	}
	if len(eventsBeforeClose) != workers*perWorker {
		t.Fatalf("expected %d flushed events before close, got %d", workers*perWorker, len(eventsBeforeClose))
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Logging after close must return an error.
	if err := logger.Log(policy.SecurityEvent{RuleID: "AFTER-CLOSE"}); err == nil {
		t.Errorf("expected error logging to closed logger")
	}

	summary := Summarize(eventsBeforeClose)
	if summary.TotalEvents != workers*perWorker {
		t.Errorf("TotalEvents = %d, want %d", summary.TotalEvents, workers*perWorker)
	}
	if summary.BySeverity[policy.SeverityCritical] == 0 || summary.BySeverity[policy.SeverityHigh] == 0 {
		t.Errorf("unexpected BySeverity: %+v", summary.BySeverity)
	}
	if summary.ByCategory["dlp"] == 0 || summary.ByCategory["ssrf"] == 0 {
		t.Errorf("unexpected ByCategory: %+v", summary.ByCategory)
	}
	if summary.ByAction["blocked"] == 0 || summary.ByAction["redacted"] == 0 || summary.ByAction["allowed"] == 0 {
		t.Errorf("unexpected ByAction: %+v", summary.ByAction)
	}
	if len(summary.TopBlockedTargets) == 0 || summary.TopBlockedTargets[0].Name != "169.254.169.254" {
		t.Errorf("expected top blocked target 169.254.169.254, got %+v", summary.TopBlockedTargets)
	}
	if len(summary.TopBlockedTools) == 0 || summary.TopBlockedTools[0].Name != "http_fetch" {
		t.Errorf("expected top blocked tool http_fetch, got %+v", summary.TopBlockedTools)
	}
	// Allowed tool read_file must NOT appear in TopBlockedTools.
	for _, tc := range summary.TopBlockedTools {
		if tc.Name == "read_file" {
			t.Errorf("allowed tool read_file leaked into TopBlockedTools: %+v", summary.TopBlockedTools)
		}
	}
}

func TestScannerOWASPMCP01ThroughMCP06AndSecretRedaction(t *testing.T) {
	rawAWSSecret := "AKIAIOSFODNN7EXAMPLE"
	rawGHSecret := "ghp_1234567890abcdefghijklmnopQRSTUV"
	rawOpenAISecret := "sk-proj-99887766554433221100aabbccddeeff"
	rawGoogleSecret := "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
	rawDBPass := "UltraSuperSecretPassword9876!"

	vulnerableJSONC := fmt.Sprintf(`{
  // Vulnerable MCP configuration covering OWASP MCP01..MCP06
  "mcpServers": {
    "unpinned-fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/", "C:\\", "~", "$HOME"],
      "env": {
        "AWS_ACCESS_KEY_ID": "%s",
        "GITHUB_TOKEN": "%s",
        "OPENAI_API_KEY": "%s",
        "GOOGLE_API_KEY": "%s",
        "DB_PASSWORD": "%s",
        "SAFE_REF": "${RUNTIME_TOKEN}",
        "NORMAL_MODE": "production",
      },
    },
    "unpinned-python": {
      "command": "uvx",
      "args": ["mcp-server-git", "--repository", "/workspace/repo"],
    },
    "unpinned-docker": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "mcp/postgres:latest"],
    },
    "shell-exec": {
      "command": "bash",
      "args": ["-c", "npx @modelcontextprotocol/server-everything"],
    },
    "win-shell": {
      "command": "powershell.exe",
      "args": ["-c", "Write-Output hi"],
    },
    "insecure-remote": {
      "url": "http://mcp.untrusted-remote.example.com:8080/sse",
    },
    "safe-loopback": {
      "url": "http://127.0.0.1:8080/mcp",
    },
  },
}`, rawAWSSecret, rawGHSecret, rawOpenAISecret, rawGoogleSecret, rawDBPass)

	report, err := AuditJSONBytes("cursor/mcp.json", []byte(vulnerableJSONC))
	if err != nil {
		t.Fatalf("AuditJSONBytes failed: %v", err)
	}

	if report.ServersChecked != 7 {
		t.Errorf("ServersChecked = %d, want 7", report.ServersChecked)
	}
	if report.RiskScore == 0 || report.Grade == "A" {
		t.Errorf("expected elevated risk score and poor grade, got score=%d grade=%s", report.RiskScore, report.Grade)
	}

	seenRules := map[string]int{}
	for _, f := range report.Findings {
		seenRules[f.RuleID]++
	}
	for _, wantRule := range []string{
		"OWASP-MCP01",
		"OWASP-MCP02",
		"OWASP-MCP03",
		"OWASP-MCP04",
		"OWASP-MCP05",
		"OWASP-MCP06",
	} {
		if seenRules[wantRule] == 0 {
			t.Errorf("expected %s to be detected, findings=%+v", wantRule, report.Findings)
		}
	}

	// Verify SAFE_REF (${RUNTIME_TOKEN}) and safe-loopback (127.0.0.1) were NOT falsely flagged.
	for _, f := range report.Findings {
		if strings.Contains(f.Evidence, "SAFE_REF") || strings.Contains(f.Message, "SAFE_REF") {
			t.Errorf("env var reference SAFE_REF was falsely flagged: %+v", f)
		}
		if f.Server == "safe-loopback" && f.RuleID == "OWASP-MCP03" {
			t.Errorf("loopback http://127.0.0.1 was falsely flagged for OWASP-MCP03: %+v", f)
		}
	}

	// ADVERSARIAL CHECK: Raw secrets must NEVER appear in findings, table, SARIF, or HTML!
	tableOut := FormatTable(report)
	sarifBytes, err := ExportSARIFReport(report)
	if err != nil {
		t.Fatalf("ExportSARIFReport failed: %v", err)
	}
	htmlOut, err := RenderAuditHTML(report)
	if err != nil {
		t.Fatalf("RenderAuditHTML failed: %v", err)
	}

	allOutputs := []struct {
		name string
		body string
	}{
		{"FormatTable", tableOut},
		{"SARIF", string(sarifBytes)},
		{"HTML", htmlOut},
	}
	rawSecrets := []string{rawAWSSecret, rawGHSecret, rawOpenAISecret, rawGoogleSecret, rawDBPass}

	for _, secret := range rawSecrets {
		for _, f := range report.Findings {
			if strings.Contains(f.Message, secret) || strings.Contains(f.Evidence, secret) || strings.Contains(f.Recommendation, secret) {
				t.Fatalf("SECRET LEAK in Finding %s: raw secret %q echoed!", f.RuleID, secret)
			}
		}
		for _, out := range allOutputs {
			if strings.Contains(out.body, secret) {
				t.Fatalf("SECRET LEAK in %s output: raw secret %q found!", out.name, secret)
			}
		}
	}

	// Verify hardened config passes with Grade A and 0 findings.
	hardenedJSON := []byte(`{
  "mcpServers": {
    "filesystem": {
      "command": "mcpgate",
      "args": ["run", "--preset", "strict", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace/my-app"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    },
    "git": {
      "command": "mcpgate",
      "args": ["run", "--preset", "strict", "--", "uvx", "mcp-server-git==0.6.2", "--repository", "/workspace/my-app"]
    },
    "remote": {
      "url": "https://mcp.example.com/sse"
    }
  }
}`)
	cleanReport, err := AuditJSONBytes("clean.json", hardenedJSON)
	if err != nil {
		t.Fatalf("AuditJSONBytes(hardened) failed: %v", err)
	}
	if len(cleanReport.Findings) != 0 || cleanReport.RiskScore != 0 || cleanReport.Grade != "A" {
		t.Errorf("expected hardened config to score A (0 findings), got grade=%s score=%d findings=%+v",
			cleanReport.Grade, cleanReport.RiskScore, cleanReport.Findings)
	}
}

func TestScannerOWASPMCP07PolicyWeaknesses(t *testing.T) {
	weakYAML := []byte(`
version: mcpgate/v1
preset: balanced
filesystem:
  block_sensitive_defaults: false
network:
  enabled: true
  block_private_ips: false
  block_cloud_metadata: false
dlp:
  enabled: false
mcp:
  block_poisoning: false
  lock_mode: off
sandbox:
  clean_env: false
`)
	report, err := AuditPolicyBytes("mcpgate.yaml", weakYAML)
	if err != nil {
		t.Fatalf("AuditPolicyBytes failed: %v", err)
	}
	if len(report.Findings) != 7 {
		t.Fatalf("expected 7 OWASP-MCP07 policy weakness findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	for _, f := range report.Findings {
		if f.RuleID != "OWASP-MCP07" {
			t.Errorf("expected OWASP-MCP07, got %s", f.RuleID)
		}
	}
	if report.RiskScore != 100 || report.Grade != "F" {
		t.Errorf("expected capped RiskScore=100 Grade=F, got %d / %s", report.RiskScore, report.Grade)
	}

	strictYAML := []byte(`
version: mcpgate/v1
preset: strict
`)
	strictReport, err := AuditPolicyBytes("mcpgate-strict.yaml", strictYAML)
	if err != nil {
		t.Fatalf("AuditPolicyBytes(strict) failed: %v", err)
	}
	if len(strictReport.Findings) != 0 || strictReport.Grade != "A" {
		t.Errorf("expected strict policy to have 0 findings and Grade A, got %+v", strictReport.Findings)
	}
}

func TestScannerAuditAllIDEsHermetic(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	appData := filepath.Join(tmp, "appdata")
	xdg := filepath.Join(tmp, "xdg")

	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", appData)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	cursorCfg, err := preset.ResolveIDEConfig("cursor")
	if err != nil {
		t.Fatalf("resolve cursor: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cursorCfg.Path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cursorCfg.Path, []byte(`{
  "mcpServers": {
    "bad": {
      "command": "cmd.exe",
      "args": ["/c", "npx @modelcontextprotocol/server-filesystem /"]
    }
  }
}`), 0600); err != nil {
		t.Fatalf("write cursor config: %v", err)
	}

	report, err := AuditAllIDEs()
	if err != nil {
		t.Fatalf("AuditAllIDEs failed: %v", err)
	}
	if len(report.ScannedFiles) != 1 {
		t.Fatalf("expected 1 scanned IDE config file, got %v", report.ScannedFiles)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected findings from auto-discovered Cursor config")
	}
}

func TestSARIF210ValidForAuditAndEvents(t *testing.T) {
	report := &AuditReport{
		GeneratedAt:    time.Now().UTC(),
		ScannedFiles:   []string{`C:\Users\Alice\.cursor\mcp.json`},
		ServersChecked: 1,
		Findings: []Finding{
			{
				RuleID:         "OWASP-MCP02",
				Title:          "Hardcoded secret",
				Severity:       policy.SeverityCritical,
				Category:       "secrets",
				File:           `C:\Users\Alice\.cursor\mcp.json`,
				Line:           12,
				Server:         "github",
				Evidence:       "env.GITHUB_TOKEN=[REDACTED]",
				Message:        "Hardcoded token detected",
				Recommendation: "Use OS keychain",
			},
			{
				RuleID:   "OWASP-MCP07",
				Title:    "Lockfile off",
				Severity: policy.SeverityMedium,
				Category: "policy",
				File:     "mcpgate.yaml",
				Message:  "lock_mode is off",
			},
			{
				RuleID:   "INFO-CHECK",
				Title:    "Informational note",
				Severity: policy.SeverityLow,
				Category: "audit",
				File:     "mcpgate.yaml",
				Message:  "Low finding",
			},
		},
	}

	raw, err := ExportSARIFReport(report)
	if err != nil {
		t.Fatalf("ExportSARIFReport failed: %v", err)
	}

	var parsed SARIFLog
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if parsed.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", parsed.Version)
	}
	if parsed.Schema != SARIFSchemaURI {
		t.Errorf("SARIF $schema = %q, want %q", parsed.Schema, SARIFSchemaURI)
	}
	if len(parsed.Runs) != 1 || parsed.Runs[0].Tool.Driver.Name != "MCPGate" {
		t.Fatalf("unexpected SARIF runs/driver: %+v", parsed.Runs)
	}
	run := parsed.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 unique rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 SARIF results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "warning" || run.Results[2].Level != "note" {
		t.Errorf("unexpected SARIF level mapping: %s, %s, %s",
			run.Results[0].Level, run.Results[1].Level, run.Results[2].Level)
	}
	uri := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if strings.Contains(uri, `\`) {
		t.Errorf("SARIF URI must use forward slashes, got %q", uri)
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Errorf("expected StartLine=12, got %+v", run.Results[0].Locations[0].PhysicalLocation.Region)
	}

	// Also test ExportSARIFEvents.
	events := []policy.SecurityEvent{
		{
			Timestamp: time.Now().UTC(),
			SessionID: "sess-1",
			Category:  "ssrf",
			Severity:  policy.SeverityCritical,
			Action:    "blocked",
			RuleID:    "MCP06-SSRF-IMDS",
			Server:    "fetch",
			Tool:      "http_get",
			Target:    "http://169.254.169.254/latest/meta-data/",
			Message:   "Blocked AWS IMDS SSRF attempt",
		},
	}
	evRaw, err := ExportSARIFEvents(events)
	if err != nil {
		t.Fatalf("ExportSARIFEvents failed: %v", err)
	}
	var evParsed SARIFLog
	if err := json.Unmarshal(evRaw, &evParsed); err != nil {
		t.Fatalf("invalid event SARIF JSON: %v", err)
	}
	if evParsed.Version != "2.1.0" || len(evParsed.Runs[0].Results) != 1 || evParsed.Runs[0].Results[0].Level != "error" {
		t.Fatalf("unexpected event SARIF output: %+v", evParsed)
	}

	// Empty report must serialize rules/results as [] rather than null.
	emptyRaw, err := ExportSARIFReport(nil)
	if err != nil {
		t.Fatalf("ExportSARIFReport(nil) failed: %v", err)
	}
	if strings.Contains(string(emptyRaw), `"results": null`) || strings.Contains(string(emptyRaw), `"rules": null`) {
		t.Errorf("SARIF empty arrays serialized as null:\n%s", string(emptyRaw))
	}
}

func TestHTMLReportXSSProtectionAndZeroExternalURLs(t *testing.T) {
	xssScript := `<script>alert(1)</script>`
	xssAttr := `"><img src=x onerror=alert(1)>`

	auditReport := &AuditReport{
		GeneratedAt:    time.Now().UTC(),
		ScannedFiles:   []string{"mcp-" + xssScript + ".json"},
		ServersChecked: 1,
		RiskScore:      40,
		Grade:          "C",
		CountsBySeverity: map[policy.Severity]int{
			policy.SeverityCritical: 1,
		},
		Findings: []Finding{
			{
				RuleID:         "OWASP-MCP02",
				Title:          "Poison " + xssScript,
				Severity:       policy.SeverityCritical,
				Category:       "secrets",
				File:           "mcp-" + xssAttr + ".json",
				Line:           5,
				Server:         "evil-" + xssScript,
				Evidence:       "env.KEY=" + xssAttr,
				Message:        "Detected " + xssScript + " and " + xssAttr,
				Recommendation: "Fix " + xssScript,
			},
		},
	}

	auditHTML, err := RenderAuditHTML(auditReport)
	if err != nil {
		t.Fatalf("RenderAuditHTML failed: %v", err)
	}

	events := []policy.SecurityEvent{
		{
			Timestamp: time.Now().UTC(),
			SessionID: "sess-" + xssScript,
			Category:  "poisoning",
			Severity:  policy.SeverityCritical,
			Action:    "quarantined",
			RuleID:    "MCP04-POISON",
			Server:    "srv-" + xssAttr,
			Tool:      "tool-" + xssScript,
			Target:    "target-" + xssAttr,
			Message:   "Tool description contained " + xssScript,
			Metadata: map[string]string{
				"payload": xssAttr,
			},
		},
	}
	eventsHTML, err := RenderEventsHTML(events, "Inspect "+xssScript)
	if err != nil {
		t.Fatalf("RenderEventsHTML failed: %v", err)
	}

	for _, tc := range []struct {
		name string
		html string
	}{
		{"AuditHTML", auditHTML},
		{"EventsHTML", eventsHTML},
	} {
		// 1. Raw XSS payloads MUST NEVER appear unescaped.
		if strings.Contains(tc.html, xssScript) {
			t.Fatalf("%s contains unescaped <script> XSS payload!", tc.name)
		}
		if strings.Contains(tc.html, xssAttr) {
			t.Fatalf("%s contains unescaped attribute-breakout XSS payload!", tc.name)
		}
		// 2. Escaped form MUST be present (proving content was rendered safely).
		if !strings.Contains(tc.html, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
			t.Errorf("%s missing escaped payload text", tc.name)
		}
		// 3. Zero unsafe DOM sinks in embedded JS.
		for _, sink := range []string{"innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "eval("} {
			if strings.Contains(tc.html, sink) {
				t.Errorf("%s uses forbidden unsafe DOM sink %q", tc.name, sink)
			}
		}
		// 4. Zero external URLs / CDN links (100% self-contained).
		if strings.Contains(strings.ToLower(tc.html), "http://") || strings.Contains(strings.ToLower(tc.html), "https://") {
			t.Errorf("%s contains an external http(s):// URL — report must be 100%% self-contained", tc.name)
		}
		// 5. Required interactive elements exist.
		for _, marker := range []string{"data-sev-filter", "data-cat-filter", `id="search-box"`, "detail-row"} {
			if !strings.Contains(tc.html, marker) {
				t.Errorf("%s missing interactive element %q", tc.name, marker)
			}
		}
	}
}
