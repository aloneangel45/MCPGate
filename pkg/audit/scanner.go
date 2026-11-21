package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
	"github.com/aloneangel45/mcpgate/pkg/preset"
)

// Finding represents a single OWASP MCP Top 10 static or configuration security issue.
// Evidence and Message are always redacted and never contain raw secret values.
type Finding struct {
	RuleID         string          `json:"rule_id"`
	Title          string          `json:"title"`
	Severity       policy.Severity `json:"severity"`
	Category       string          `json:"category"`
	File           string          `json:"file"`
	Line           int             `json:"line,omitempty"`
	Server         string          `json:"server,omitempty"`
	Evidence       string          `json:"evidence,omitempty"`
	Message        string          `json:"message"`
	Recommendation string          `json:"recommendation"`
}

// AuditReport aggregates findings, risk scoring, and severity breakdown across audited configs.
type AuditReport struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	ScannedFiles     []string                `json:"scanned_files"`
	ServersChecked   int                     `json:"servers_checked"`
	Findings         []Finding               `json:"findings"`
	RiskScore        int                     `json:"risk_score"`
	Grade            string                  `json:"grade"`
	CountsBySeverity map[policy.Severity]int `json:"counts_by_severity"`
}

type secretPattern struct {
	label string
	re    *regexp.Regexp
}

var (
	semverPinRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$`)
	driveRootRE = regexp.MustCompile(`^[A-Za-z]:[\\/]?$`)
	urlInArgRE  = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)

	secretValuePatterns = []secretPattern{
		{label: "AWS Access Key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{label: "GitHub Token", re: regexp.MustCompile(`\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b`)},
		{label: "API Secret Key", re: regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}\b|\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
		{label: "Google API Key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{20,}\b`)},
		{label: "Slack Token", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
		{label: "GitLab Token", re: regexp.MustCompile(`\bglpat-[0-9A-Za-z\-_]{16,}\b`)},
		{label: "Private Key PEM", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	}

	sensitiveKeySuffixes = []string{
		"_TOKEN",
		"_KEY",
		"_SECRET",
		"_PASSWORD",
		"_PASSWD",
		"_PWD",
		"_APIKEY",
		"_API_KEY",
		"_CREDENTIAL",
		"_CREDENTIALS",
		"_AUTH",
		"_PAT",
		"_BEARER",
	}

	sensitiveKeyExact = map[string]bool{
		"TOKEN":          true,
		"SECRET":         true,
		"PASSWORD":       true,
		"PASSWD":         true,
		"API_KEY":        true,
		"APIKEY":         true,
		"ACCESS_TOKEN":   true,
		"AUTH_TOKEN":     true,
		"PRIVATE_KEY":    true,
		"AUTHORIZATION":  true,
		"CLIENT_SECRET":  true,
		"DATABASE_URL":   true,
		"DB_URL":         true,
		"CONNECTION_URL": true,
	}

	highRiskServerKeywords = []string{
		"filesystem",
		"file-system",
		"file_system",
		"fs-mcp",
		"shell",
		"bash",
		"terminal",
		"exec",
		"command",
		"powershell",
		"desktop-commander",
		"iterm",
		"postgres",
		"postgresql",
		"mysql",
		"sqlite",
		"mariadb",
		"mssql",
		"mongodb",
		"redis",
		"supabase",
		"database",
		"git",
		"github",
		"gitlab",
		"docker",
		"kubernetes",
		"kubectl",
		"k8s",
		"terraform",
		"aws",
		"gcloud",
		"azure",
		"playwright",
		"puppeteer",
		"browser",
	}
)

// AuditFile audits a single MCP JSON/JSONC configuration file or mcpgate.yaml policy file.
func AuditFile(path string) (*AuditReport, error) {
	return AuditFiles([]string{path})
}

// AuditAllIDEs discovers all existing IDE MCP configuration files on the host and audits them.
func AuditAllIDEs() (*AuditReport, error) {
	discovered := preset.DiscoverIDEConfigs()
	paths := make([]string, 0, len(discovered))
	for _, cfg := range discovered {
		paths = append(paths, cfg.Path)
	}
	return AuditFiles(paths)
}

// AuditFiles audits one or more MCP configuration or mcpgate.yaml policy files.
func AuditFiles(paths []string) (*AuditReport, error) {
	report := newAuditReport()
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read audit target %q: %w", p, err)
		}
		report.ScannedFiles = append(report.ScannedFiles, p)

		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			if err := auditPolicyData(p, data, report); err != nil {
				return nil, err
			}
			continue
		}
		if err := auditMCPConfigData(p, data, report); err != nil {
			return nil, err
		}
	}
	finalizeReport(report)
	return report, nil
}

// AuditJSONBytes audits raw JSON or JSONC MCP configuration bytes in memory.
func AuditJSONBytes(sourceName string, data []byte) (*AuditReport, error) {
	report := newAuditReport()
	if sourceName != "" {
		report.ScannedFiles = append(report.ScannedFiles, sourceName)
	}
	if err := auditMCPConfigData(sourceName, data, report); err != nil {
		return nil, err
	}
	finalizeReport(report)
	return report, nil
}

// AuditPolicyBytes audits raw mcpgate.yaml policy bytes in memory.
func AuditPolicyBytes(sourceName string, data []byte) (*AuditReport, error) {
	report := newAuditReport()
	if sourceName != "" {
		report.ScannedFiles = append(report.ScannedFiles, sourceName)
	}
	if err := auditPolicyData(sourceName, data, report); err != nil {
		return nil, err
	}
	finalizeReport(report)
	return report, nil
}

func newAuditReport() *AuditReport {
	return &AuditReport{
		GeneratedAt:      time.Now().UTC(),
		ScannedFiles:     []string{},
		Findings:         []Finding{},
		CountsBySeverity: map[policy.Severity]int{},
	}
}

func finalizeReport(r *AuditReport) {
	score := 0
	counts := map[policy.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
		score += severityWeight(f.Severity)
	}
	if score > 100 {
		score = 100
	}
	r.RiskScore = score
	r.Grade = scoreToGrade(score)
	r.CountsBySeverity = counts

	sort.SliceStable(r.Findings, func(i, j int) bool {
		wi, wj := severityWeight(r.Findings[i].Severity), severityWeight(r.Findings[j].Severity)
		if wi != wj {
			return wi > wj
		}
		if r.Findings[i].RuleID != r.Findings[j].RuleID {
			return r.Findings[i].RuleID < r.Findings[j].RuleID
		}
		if r.Findings[i].File != r.Findings[j].File {
			return r.Findings[i].File < r.Findings[j].File
		}
		return r.Findings[i].Server < r.Findings[j].Server
	})
}

func severityWeight(sev policy.Severity) int {
	switch sev {
	case policy.SeverityCritical:
		return 25
	case policy.SeverityHigh:
		return 15
	case policy.SeverityMedium:
		return 8
	case policy.SeverityLow:
		return 3
	default:
		return 1
	}
}

func scoreToGrade(score int) string {
	switch {
	case score <= 10:
		return "A"
	case score <= 25:
		return "B"
	case score <= 45:
		return "C"
	case score <= 70:
		return "D"
	default:
		return "F"
	}
}

type parsedServer struct {
	name    string
	command string
	args    []string
	env     map[string]string
	headers map[string]string
	urls    []string
	line    int
}

func auditMCPConfigData(source string, raw []byte, report *AuditReport) error {
	cleaned := bytes.TrimSpace(preset.StripJSONC(raw))
	if len(cleaned) == 0 {
		return nil
	}

	var doc map[string]any
	if err := json.Unmarshal(cleaned, &doc); err != nil {
		return fmt.Errorf("parse MCP config %q: %w", source, err)
	}

	rawStr := string(raw)
	servers := extractServers(doc, rawStr)
	for _, srv := range servers {
		report.ServersChecked++
		auditServer(source, srv, report)
	}
	return nil
}

func extractServers(doc map[string]any, rawText string) []parsedServer {
	var out []parsedServer
	for _, key := range []string{"mcpServers", "servers", "context_servers"} {
		m, ok := doc[key].(map[string]any)
		if !ok {
			continue
		}
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)

		for _, name := range names {
			obj, ok := m[name].(map[string]any)
			if !ok {
				continue
			}
			ps := parsedServer{
				name:    name,
				env:     map[string]string{},
				headers: map[string]string{},
				line:    findJSONKeyLine(rawText, name),
			}

			// Support Zed nested command object {"command": {"path": "...", "args": [...], "env": {...}}}
			if cmdObj, ok := obj["command"].(map[string]any); ok {
				ps.command, _ = cmdObj["path"].(string)
				ps.args = anyToStringSlice(cmdObj["args"])
				mergeStringMap(ps.env, cmdObj["env"])
			} else {
				ps.command, _ = obj["command"].(string)
				ps.args = anyToStringSlice(obj["args"])
			}

			mergeStringMap(ps.env, obj["env"])
			mergeStringMap(ps.headers, obj["headers"])

			for _, urlField := range []string{"url", "serverUrl", "baseUrl", "endpoint", "httpUrl"} {
				if u, ok := obj[urlField].(string); ok && strings.TrimSpace(u) != "" {
					ps.urls = append(ps.urls, strings.TrimSpace(u))
				}
			}

			out = append(out, ps)
		}
	}
	return out
}

func auditServer(source string, srv parsedServer, report *AuditReport) {
	rawCmd := strings.TrimSpace(srv.command)
	rawArgs := srv.args

	// Determine whether server is wrapped by MCPGate or ToolPrune.
	wrapped := isWrappedCommand(rawCmd)

	// Unwrap MCPGate / ToolPrune invocation so we still audit the underlying command
	// for OWASP-MCP01 (supply chain), OWASP-MCP05 (broad roots), and OWASP-MCP06 (shell).
	effectiveCmd, effectiveArgs := rawCmd, rawArgs
	if origCmd, origArgs, ok := preset.ExtractWrappedCommand(rawCmd, rawArgs); ok {
		effectiveCmd, effectiveArgs = origCmd, origArgs
	}

	// OWASP-MCP01: Unpinned remote package execution (npx, uvx, docker run).
	checkMCP01Unpinned(source, srv.name, srv.line, effectiveCmd, effectiveArgs, report)

	// OWASP-MCP02: Hardcoded plaintext secrets in env blocks, headers, or docker -e args.
	checkMCP02Secrets(source, srv, report)

	// OWASP-MCP03: Unencrypted non-loopback http:// remote endpoints.
	checkMCP03Transport(source, srv, effectiveArgs, report)

	// OWASP-MCP04: Unwrapped high-risk local MCP servers.
	if rawCmd != "" && !wrapped {
		checkMCP04Unwrapped(source, srv.name, srv.line, rawCmd, rawArgs, report)
	}

	// OWASP-MCP05: Overly broad filesystem roots passed in args.
	checkMCP05BroadRoots(source, srv.name, srv.line, effectiveArgs, report)

	// OWASP-MCP06: Shell interpreter indirection (sh -c, bash -c, cmd /c, powershell -c).
	checkMCP06ShellIndirection(source, srv.name, srv.line, effectiveCmd, effectiveArgs, report)
}

func checkMCP01Unpinned(source, server string, line int, cmd string, args []string, report *AuditReport) {
	if cmd == "" {
		return
	}
	base := normalizedBinName(cmd)

	switch base {
	case "npx", "pnpx", "bunx":
		pkg := extractNPXPackage(args)
		if pkg == "" || isLocalPath(pkg) {
			return
		}
		if !isPinnedNPMPackage(pkg) {
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP01",
				Title:          "Unpinned remote NPM package execution",
				Severity:       policy.SeverityHigh,
				Category:       "supply_chain",
				File:           source,
				Line:           line,
				Server:         server,
				Evidence:       fmt.Sprintf("%s %s", base, pkg),
				Message:        fmt.Sprintf("Server %q executes unpinned package %q via %s; upstream compromises can silently hijack the server.", server, pkg, base),
				Recommendation: fmt.Sprintf("Pin an exact version (e.g. %s@x.y.z) and enable MCPGate tool schema lockfile enforcement.", stripNPMSpecVersion(pkg)),
			})
		}

	case "uvx", "pipx":
		pkg := extractUVXPackage(base, args)
		if pkg == "" || isLocalPath(pkg) {
			return
		}
		if !isPinnedPythonPackage(pkg) {
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP01",
				Title:          "Unpinned remote Python package execution",
				Severity:       policy.SeverityHigh,
				Category:       "supply_chain",
				File:           source,
				Line:           line,
				Server:         server,
				Evidence:       fmt.Sprintf("%s %s", base, pkg),
				Message:        fmt.Sprintf("Server %q executes unpinned Python package %q via %s without an exact ==x.y.z version pin.", server, pkg, base),
				Recommendation: fmt.Sprintf("Pin an exact package version (e.g. %s==x.y.z) to prevent supply-chain drift.", stripPythonSpecVersion(pkg)),
			})
		}

	case "docker", "podman":
		img := extractDockerRunImage(args)
		if img == "" {
			return
		}
		if !isPinnedDockerImage(img) {
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP01",
				Title:          "Unpinned container image execution",
				Severity:       policy.SeverityHigh,
				Category:       "supply_chain",
				File:           source,
				Line:           line,
				Server:         server,
				Evidence:       fmt.Sprintf("%s run %s", base, img),
				Message:        fmt.Sprintf("Server %q launches mutable container image %q without an immutable version tag or SHA256 digest.", server, img),
				Recommendation: "Pin the container image to an immutable @sha256:... digest or an explicit semantic version tag instead of :latest.",
			})
		}
	}
}

func checkMCP02Secrets(source string, srv parsedServer, report *AuditReport) {
	// Check env block (sorted keys for deterministic output).
	envKeys := make([]string, 0, len(srv.env))
	for k := range srv.env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)

	for _, k := range envKeys {
		val := strings.TrimSpace(srv.env[k])
		if val == "" || isPlaceholderOrEnvRef(val) {
			continue
		}
		if label, matched := matchSecretValue(val); matched {
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP02",
				Title:          "Hardcoded plaintext secret in MCP env configuration",
				Severity:       policy.SeverityCritical,
				Category:       "secrets",
				File:           source,
				Line:           srv.line,
				Server:         srv.name,
				Evidence:       fmt.Sprintf("env.%s=[REDACTED: %s]", k, label),
				Message:        fmt.Sprintf("Server %q stores a hardcoded %s in env.%s (value redacted).", srv.name, label, k),
				Recommendation: "Remove plaintext secrets from IDE MCP configs; inject credentials via OS keychain, secret manager, or environment variable references.",
			})
			continue
		}
		if isSensitiveEnvKey(k) {
			// For DATABASE_URL/DB_URL, only flag when embedded credentials exist (user:pass@).
			upper := strings.ToUpper(strings.TrimSpace(k))
			if (upper == "DATABASE_URL" || upper == "DB_URL" || upper == "CONNECTION_URL") && !hasEmbeddedURLCreds(val) {
				continue
			}
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP02",
				Title:          "Hardcoded plaintext credential in MCP env configuration",
				Severity:       policy.SeverityCritical,
				Category:       "secrets",
				File:           source,
				Line:           srv.line,
				Server:         srv.name,
				Evidence:       fmt.Sprintf("env.%s=[REDACTED]", k),
				Message:        fmt.Sprintf("Server %q contains a hardcoded plaintext credential in env.%s (value redacted).", srv.name, k),
				Recommendation: "Move sensitive tokens/keys out of MCP config files and reference them securely via your OS keychain or runtime secret store.",
			})
		}
	}

	// Check HTTP headers block (e.g. Authorization: Bearer ...).
	hdrKeys := make([]string, 0, len(srv.headers))
	for k := range srv.headers {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)

	for _, k := range hdrKeys {
		val := strings.TrimSpace(srv.headers[k])
		if val == "" || isPlaceholderOrEnvRef(val) {
			continue
		}
		if label, matched := matchSecretValue(val); matched {
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP02",
				Title:          "Hardcoded plaintext secret in MCP HTTP header",
				Severity:       policy.SeverityCritical,
				Category:       "secrets",
				File:           source,
				Line:           srv.line,
				Server:         srv.name,
				Evidence:       fmt.Sprintf("headers.%s=[REDACTED: %s]", k, label),
				Message:        fmt.Sprintf("Server %q embeds a hardcoded %s in HTTP header %q (value redacted).", srv.name, label, k),
				Recommendation: "Never hardcode API tokens in static MCP header configs; use short-lived OAuth tokens or runtime secret injection.",
			})
		} else if isSensitiveEnvKey(k) {
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP02",
				Title:          "Hardcoded authentication header in MCP configuration",
				Severity:       policy.SeverityCritical,
				Category:       "secrets",
				File:           source,
				Line:           srv.line,
				Server:         srv.name,
				Evidence:       fmt.Sprintf("headers.%s=[REDACTED]", k),
				Message:        fmt.Sprintf("Server %q embeds a plaintext credential in HTTP header %q (value redacted).", srv.name, k),
				Recommendation: "Store authentication credentials in a secret manager or environment variable reference rather than plaintext config JSON.",
			})
		}
	}

	// Also check inline docker `-e KEY=VALUE` / `--env KEY=VALUE` arguments.
	for i := 0; i < len(srv.args); i++ {
		arg := srv.args[i]
		var kv string
		if (arg == "-e" || arg == "--env") && i+1 < len(srv.args) {
			kv = srv.args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--env=") {
			kv = strings.TrimPrefix(arg, "--env=")
		}
		if k, v, ok := strings.Cut(kv, "="); ok {
			v = strings.TrimSpace(v)
			if v == "" || isPlaceholderOrEnvRef(v) {
				continue
			}
			if label, matched := matchSecretValue(v); matched {
				report.Findings = append(report.Findings, Finding{
					RuleID:         "OWASP-MCP02",
					Title:          "Hardcoded plaintext secret in container launch args",
					Severity:       policy.SeverityCritical,
					Category:       "secrets",
					File:           source,
					Line:           srv.line,
					Server:         srv.name,
					Evidence:       fmt.Sprintf("args.-e.%s=[REDACTED: %s]", k, label),
					Message:        fmt.Sprintf("Server %q passes a hardcoded %s via CLI env flag %s (value redacted).", srv.name, label, k),
					Recommendation: "Pass only the variable name (-e VAR) so the runtime inherits it securely without storing secrets in config JSON.",
				})
			} else if isSensitiveEnvKey(k) {
				report.Findings = append(report.Findings, Finding{
					RuleID:         "OWASP-MCP02",
					Title:          "Hardcoded credential in container launch args",
					Severity:       policy.SeverityCritical,
					Category:       "secrets",
					File:           source,
					Line:           srv.line,
					Server:         srv.name,
					Evidence:       fmt.Sprintf("args.-e.%s=[REDACTED]", k),
					Message:        fmt.Sprintf("Server %q passes a plaintext credential via CLI env flag %s (value redacted).", srv.name, k),
					Recommendation: "Pass only the variable name (-e VAR) without an inline secret value.",
				})
			}
		}
	}
}

func checkMCP03Transport(source string, srv parsedServer, args []string, report *AuditReport) {
	seen := map[string]bool{}
	candidates := append([]string(nil), srv.urls...)
	for _, a := range args {
		for _, m := range urlInArgRE.FindAllString(a, -1) {
			candidates = append(candidates, m)
		}
	}

	for _, rawURL := range candidates {
		u, err := url.Parse(rawURL)
		if err != nil || !strings.EqualFold(u.Scheme, "http") {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host == "" || isLoopbackHost(host) {
			continue
		}
		sanitized := fmt.Sprintf("http://%s%s", u.Host, u.Path)
		if seen[sanitized] {
			continue
		}
		seen[sanitized] = true

		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP03",
			Title:          "Unencrypted remote HTTP MCP endpoint",
			Severity:       policy.SeverityHigh,
			Category:       "transport",
			File:           source,
			Line:           srv.line,
			Server:         srv.name,
			Evidence:       sanitized,
			Message:        fmt.Sprintf("Server %q communicates with non-loopback endpoint %q over plaintext HTTP, exposing tool calls and tokens to MITM interception.", srv.name, sanitized),
			Recommendation: "Switch the remote MCP endpoint to HTTPS (TLS 1.2+) or tunnel traffic over an encrypted VPN/SSH connection.",
		})
	}
}

func checkMCP04Unwrapped(source, server string, line int, cmd string, args []string, report *AuditReport) {
	haystack := strings.ToLower(server + " " + cmd + " " + strings.Join(args, " "))
	matchedKind := ""
	for _, kw := range highRiskServerKeywords {
		if strings.Contains(haystack, kw) {
			matchedKind = kw
			break
		}
	}
	if matchedKind == "" {
		return
	}

	report.Findings = append(report.Findings, Finding{
		RuleID:         "OWASP-MCP04",
		Title:          "Unwrapped high-risk local MCP server",
		Severity:       policy.SeverityHigh,
		Category:       "isolation",
		File:           source,
		Line:           line,
		Server:         server,
		Evidence:       fmt.Sprintf("command=%s (category=%s)", cmd, matchedKind),
		Message:        fmt.Sprintf("High-risk local MCP server %q (%s) runs directly without MCPGate or ToolPrune zero-trust runtime protection.", server, matchedKind),
		Recommendation: "Wrap this server using `mcpgate preset install` or launch it through `mcpgate run --preset strict -- ...` to enforce DLP, SSRF, path confinement, and tool poisoning guards.",
	})
}

func checkMCP05BroadRoots(source, server string, line int, args []string, report *AuditReport) {
	reported := map[string]bool{}
	for i := 0; i < len(args); i++ {
		rawArg := strings.TrimSpace(args[i])
		if rawArg == "" {
			continue
		}

		// Inspect docker bind mounts like `-v /:/host` or `--volume C:\:/host`.
		if (rawArg == "-v" || rawArg == "--volume") && i+1 < len(args) {
			mountSpec := strings.TrimSpace(args[i+1])
			hostPart := extractMountHostPath(mountSpec)
			if isBroadFilesystemRoot(hostPart) && !reported[hostPart] {
				reported[hostPart] = true
				report.Findings = append(report.Findings, Finding{
					RuleID:         "OWASP-MCP05",
					Title:          "Overly broad filesystem root exposed to MCP server",
					Severity:       policy.SeverityHigh,
					Category:       "filesystem",
					File:           source,
					Line:           line,
					Server:         server,
					Evidence:       fmt.Sprintf("volume=%s", hostPart),
					Message:        fmt.Sprintf("Server %q mounts broad host filesystem root %q into a container.", server, hostPart),
					Recommendation: "Restrict MCP filesystem roots and container mounts to the narrowest project directory required.",
				})
			}
			i++
			continue
		}

		// Handle flag=value forms like --root=/ or --allowed-dir=~
		candidate := rawArg
		if strings.HasPrefix(rawArg, "-") {
			if _, val, ok := strings.Cut(rawArg, "="); ok {
				candidate = strings.TrimSpace(val)
			} else {
				continue
			}
		}

		if isBroadFilesystemRoot(candidate) && !reported[candidate] {
			reported[candidate] = true
			report.Findings = append(report.Findings, Finding{
				RuleID:         "OWASP-MCP05",
				Title:          "Overly broad filesystem root in MCP server arguments",
				Severity:       policy.SeverityHigh,
				Category:       "filesystem",
				File:           source,
				Line:           line,
				Server:         server,
				Evidence:       fmt.Sprintf("arg=%s", candidate),
				Message:        fmt.Sprintf("Server %q grants access to broad filesystem root %q, exposing SSH keys, cloud credentials, and system files.", server, candidate),
				Recommendation: "Scope filesystem arguments to a single dedicated workspace folder and enforce MCPGate filesystem allow_paths.",
			})
		}
	}
}

func checkMCP06ShellIndirection(source, server string, line int, cmd string, args []string, report *AuditReport) {
	if cmd == "" {
		return
	}
	base := normalizedBinName(cmd)
	checkArgs := args

	// Unwrap `/usr/bin/env bash -c ...` indirection.
	if base == "env" && len(args) >= 2 {
		for idx, a := range args {
			if !strings.HasPrefix(a, "-") && !strings.Contains(a, "=") {
				base = normalizedBinName(a)
				checkArgs = args[idx+1:]
				break
			}
		}
	}

	flagged := false
	matchedFlag := ""
	switch base {
	case "sh", "bash", "zsh", "dash", "ash", "ksh", "fish":
		for _, a := range checkArgs {
			if a == "-c" || a == "-lc" || a == "-ic" || a == "-ec" {
				flagged = true
				matchedFlag = a
				break
			}
		}
	case "cmd":
		for _, a := range checkArgs {
			la := strings.ToLower(a)
			if la == "/c" || la == "/k" || la == "-c" {
				flagged = true
				matchedFlag = a
				break
			}
		}
	case "powershell", "pwsh":
		for _, a := range checkArgs {
			la := strings.ToLower(a)
			if la == "-c" || la == "-command" || la == "-enc" || la == "-encodedcommand" {
				flagged = true
				matchedFlag = a
				break
			}
		}
	}

	if flagged {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP06",
			Title:          "Shell interpreter indirection in MCP launch command",
			Severity:       policy.SeverityHigh,
			Category:       "execution",
			File:           source,
			Line:           line,
			Server:         server,
			Evidence:       fmt.Sprintf("%s %s ...", base, matchedFlag),
			Message:        fmt.Sprintf("Server %q launches via shell interpreter indirection (%s %s), increasing command injection risk and bypassing direct binary auditing.", server, base, matchedFlag),
			Recommendation: "Invoke the MCP server executable directly with explicit JSON argument arrays instead of wrapping commands in a shell.",
		})
	}
}

func auditPolicyData(source string, raw []byte, report *AuditReport) error {
	p, err := policy.ParseYAML(raw)
	if err != nil {
		return fmt.Errorf("parse mcpgate policy %q: %w", source, err)
	}

	if !p.DLP.Enabled {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "DLP secret exfiltration protection disabled",
			Severity:       policy.SeverityCritical,
			Category:       "policy",
			File:           source,
			Evidence:       "dlp.enabled: false",
			Message:        "Policy disables live DLP scanning (`dlp.enabled: false`), allowing API keys and credentials to leak via MCP tool calls or egress.",
			Recommendation: "Set `dlp.enabled: true` and `dlp.action: block` (or `redact`).",
		})
	}

	if !p.Network.BlockCloudMetadata {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "Cloud metadata SSRF protection disabled",
			Severity:       policy.SeverityCritical,
			Category:       "policy",
			File:           source,
			Evidence:       "network.block_cloud_metadata: false",
			Message:        "Policy disables cloud IMDS SSRF blocking (`network.block_cloud_metadata: false`), exposing 169.254.169.254 and metadata endpoints.",
			Recommendation: "Set `network.block_cloud_metadata: true` to block SSRF attacks targeting cloud instance credentials.",
		})
	}

	if !p.Network.BlockPrivateIPs {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "Private/RFC1918 IP SSRF blocking disabled",
			Severity:       policy.SeverityHigh,
			Category:       "policy",
			File:           source,
			Evidence:       "network.block_private_ips: false",
			Message:        "Policy allows outbound connections to private/internal IP ranges (`network.block_private_ips: false`).",
			Recommendation: "Set `network.block_private_ips: true` to prevent SSRF lateral movement inside internal networks.",
		})
	}

	lockMode := strings.ToLower(strings.TrimSpace(p.MCP.LockMode))
	if lockMode == "" || lockMode == "off" {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "MCP tool schema lockfile (rug-pull protection) disabled",
			Severity:       policy.SeverityMedium,
			Category:       "policy",
			File:           source,
			Evidence:       "mcp.lock_mode: off",
			Message:        "Policy disables MCP tool schema lockfile verification (`mcp.lock_mode: off`), leaving sessions exposed to silent tool rug-pulls.",
			Recommendation: "Set `mcp.lock_mode: enforce` (or `warn` during rollout) to detect mid-session or upstream tool schema mutations.",
		})
	}

	if !p.MCP.BlockPoisoning {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "MCP tool poisoning detection disabled",
			Severity:       policy.SeverityHigh,
			Category:       "policy",
			File:           source,
			Evidence:       "mcp.block_poisoning: false",
			Message:        "Policy disables live prompt-injection & tool poisoning inspection (`mcp.block_poisoning: false`).",
			Recommendation: "Set `mcp.block_poisoning: true` and `mcp.quarantine_poisoned: true`.",
		})
	}

	if !p.Filesystem.BlockSensitiveDefaults {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "Sensitive credential path guard disabled",
			Severity:       policy.SeverityHigh,
			Category:       "policy",
			File:           source,
			Evidence:       "filesystem.block_sensitive_defaults: false",
			Message:        "Policy disables built-in protection for ~/.ssh, ~/.aws, .env, and credential paths (`filesystem.block_sensitive_defaults: false`).",
			Recommendation: "Set `filesystem.block_sensitive_defaults: true`.",
		})
	}

	if !p.Sandbox.CleanEnv {
		report.Findings = append(report.Findings, Finding{
			RuleID:         "OWASP-MCP07",
			Title:          "Subprocess environment scrubbing disabled",
			Severity:       policy.SeverityMedium,
			Category:       "policy",
			File:           source,
			Evidence:       "sandbox.clean_env: false",
			Message:        "Policy passes the full host environment to child MCP servers (`sandbox.clean_env: false`), risking credential harvesting.",
			Recommendation: "Set `sandbox.clean_env: true` and explicitly allowlist only required variables via `sandbox.pass_env`.",
		})
	}

	return nil
}

// FormatTable renders an AuditReport as a clean, aligned plain-text console table.
func FormatTable(report *AuditReport) string {
	if report == nil {
		return "No audit report available.\n"
	}

	var b strings.Builder
	b.WriteString("MCPGate OWASP MCP Top 10 Security Audit\n")
	b.WriteString(strings.Repeat("=", 78) + "\n")
	fmt.Fprintf(&b, "Grade: %s   Risk Score: %d/100   Files: %d   Servers: %d   Findings: %d\n",
		report.Grade, report.RiskScore, len(report.ScannedFiles), report.ServersChecked, len(report.Findings))
	fmt.Fprintf(&b, "Severity Breakdown: Critical=%d  High=%d  Medium=%d  Low=%d  Info=%d\n",
		report.CountsBySeverity[policy.SeverityCritical],
		report.CountsBySeverity[policy.SeverityHigh],
		report.CountsBySeverity[policy.SeverityMedium],
		report.CountsBySeverity[policy.SeverityLow],
		report.CountsBySeverity[policy.SeverityInfo],
	)
	b.WriteString(strings.Repeat("-", 78) + "\n")

	if len(report.Findings) == 0 {
		b.WriteString("PASS: No security issues detected.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "%-12s %-9s %-18s %s\n", "RULE", "SEVERITY", "SERVER", "DETAILS")
	b.WriteString(strings.Repeat("-", 78) + "\n")
	for _, f := range report.Findings {
		srv := f.Server
		if srv == "" {
			srv = filepath.Base(f.File)
		}
		if len(srv) > 18 {
			srv = srv[:15] + "..."
		}
		sev := strings.ToUpper(string(f.Severity))
		fmt.Fprintf(&b, "%-12s %-9s %-18s %s\n", f.RuleID, sev, srv, f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "%-12s %-9s %-18s Evidence: %s\n", "", "", "", f.Evidence)
		}
	}
	return b.String()
}

// --- Helper functions ---

func normalizedBinName(cmd string) string {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(cmd)))
	for _, suffix := range []string{".exe", ".cmd", ".bat"} {
		base = strings.TrimSuffix(base, suffix)
	}
	return base
}

func isWrappedCommand(cmd string) bool {
	base := normalizedBinName(cmd)
	return base == "mcpgate" || base == "toolprune"
}

func extractNPXPackage(args []string) string {
	takeNext := false
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if takeNext {
			return a
		}
		if a == "-p" || a == "--package" {
			takeNext = true
			continue
		}
		if strings.HasPrefix(a, "--package=") {
			return strings.TrimPrefix(a, "--package=")
		}
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func isPinnedNPMPackage(spec string) bool {
	s := strings.TrimSpace(spec)
	if s == "" {
		return true
	}
	// Scoped package: @scope/name@1.2.3
	var ver string
	if strings.HasPrefix(s, "@") {
		rest := s[1:]
		idx := strings.IndexByte(rest, '@')
		if idx < 0 {
			return false
		}
		ver = rest[idx+1:]
	} else {
		idx := strings.IndexByte(s, '@')
		if idx < 0 {
			return false
		}
		ver = s[idx+1:]
	}
	return semverPinRE.MatchString(ver)
}

func stripNPMSpecVersion(spec string) string {
	if strings.HasPrefix(spec, "@") {
		rest := spec[1:]
		if idx := strings.IndexByte(rest, '@'); idx >= 0 {
			return "@" + rest[:idx]
		}
		return spec
	}
	if idx := strings.IndexByte(spec, '@'); idx >= 0 {
		return spec[:idx]
	}
	return spec
}

func extractUVXPackage(base string, args []string) string {
	start := 0
	if base == "pipx" {
		if len(args) == 0 || strings.ToLower(args[0]) != "run" {
			return ""
		}
		start = 1
	}

	skipNext := false
	takeNext := false
	for i := start; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		if a == "" {
			continue
		}
		if takeNext {
			return a
		}
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--from" {
			takeNext = true
			continue
		}
		if strings.HasPrefix(a, "--from=") {
			return strings.TrimPrefix(a, "--from=")
		}
		if a == "--python" || a == "-p" || a == "--with" || a == "--index-url" || a == "--extra-index-url" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func isPinnedPythonPackage(spec string) bool {
	s := strings.TrimSpace(spec)
	// Strip extras like pkg[extra]==1.2.3
	idx := strings.Index(s, "==")
	if idx < 0 {
		return false
	}
	ver := strings.TrimSpace(s[idx+2:])
	return semverPinRE.MatchString(ver)
}

func stripPythonSpecVersion(spec string) string {
	for _, sep := range []string{"==", ">=", "<=", "~=", "!=", "@"} {
		if idx := strings.Index(spec, sep); idx >= 0 {
			return spec[:idx]
		}
	}
	return spec
}

func extractDockerRunImage(args []string) string {
	runIdx := -1
	for i, a := range args {
		if strings.EqualFold(strings.TrimSpace(a), "run") {
			runIdx = i
			break
		}
	}
	if runIdx < 0 {
		return ""
	}

	valueFlags := map[string]bool{
		"-e": true, "--env": true, "--env-file": true,
		"-v": true, "--volume": true, "--mount": true,
		"-p": true, "--publish": true,
		"-w": true, "--workdir": true,
		"-u": true, "--user": true,
		"-l": true, "--label": true,
		"-h": true, "--hostname": true,
		"--name": true, "--network": true, "--net": true,
		"--entrypoint": true, "--platform": true, "--pull": true,
		"--cap-add": true, "--cap-drop": true, "--security-opt": true,
		"--memory": true, "-m": true, "--cpus": true, "--pids-limit": true,
		"--add-host": true, "--dns": true, "--restart": true,
	}

	skipNext := false
	for i := runIdx + 1; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		if a == "" {
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		if valueFlags[a] {
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func isPinnedDockerImage(img string) bool {
	s := strings.TrimSpace(img)
	if s == "" {
		return true
	}
	// Immutable digest pin: repo/image@sha256:<64 hex>
	if idx := strings.Index(s, "@sha256:"); idx >= 0 && len(s[idx+8:]) >= 16 {
		return true
	}
	// Tag check: look for ':' after last '/' so registry port (localhost:5000/img) isn't confused for a tag.
	lastSlash := strings.LastIndexByte(s, '/')
	tail := s
	if lastSlash >= 0 {
		tail = s[lastSlash+1:]
	}
	colon := strings.IndexByte(tail, ':')
	if colon < 0 {
		return false
	}
	tag := strings.ToLower(strings.TrimSpace(tail[colon+1:]))
	switch tag {
	case "", "latest", "main", "master", "edge", "dev", "nightly", "canary", "stable":
		return false
	default:
		return true
	}
}

func isLocalPath(spec string) bool {
	return strings.HasPrefix(spec, "./") ||
		strings.HasPrefix(spec, "../") ||
		strings.HasPrefix(spec, "/") ||
		strings.HasPrefix(spec, `.\`) ||
		strings.HasPrefix(spec, `..\`)
}

func matchSecretValue(val string) (string, bool) {
	for _, pat := range secretValuePatterns {
		if pat.re.MatchString(val) {
			return pat.label, true
		}
	}
	return "", false
}

func isSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return false
	}
	if sensitiveKeyExact[upper] {
		return true
	}
	for _, suffix := range sensitiveKeySuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

func isPlaceholderOrEnvRef(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" {
		return true
	}
	// Variable references: $VAR, ${VAR}, ${env:VAR}, {{VAR}}, %VAR%
	if (strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}")) ||
		(strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}")) ||
		(strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%") && len(v) > 2) ||
		(strings.HasPrefix(v, "$") && !strings.ContainsAny(v, " \t/\\:")) {
		return true
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return true
	}
	lower := strings.ToLower(v)
	switch lower {
	case "true", "false", "0", "1", "null", "none", "changeme", "placeholder", "example", "replace_me", "todo":
		return true
	}
	if strings.HasPrefix(lower, "your_") || strings.HasPrefix(lower, "your-") || strings.HasPrefix(lower, "replace_") {
		return true
	}
	return false
}

func hasEmbeddedURLCreds(val string) bool {
	u, err := url.Parse(val)
	if err != nil || u.User == nil {
		return false
	}
	_, hasPass := u.User.Password()
	return hasPass
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isBroadFilesystemRoot(arg string) bool {
	s := strings.Trim(strings.TrimSpace(arg), `"'`)
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	switch lower {
	case "/", `\`, "~", "~/", `~\`, "$home", "${home}", "$home/", "${home}/",
		"%userprofile%", "%userprofile%\\", "%home%", "%homedrive%", "%homedrive%\\",
		"%systemdrive%", "%systemdrive%\\", "/users", "/home", "/etc", `c:\users`, "c:/users":
		return true
	}
	return driveRootRE.MatchString(s)
}

func extractMountHostPath(spec string) string {
	// Windows bind mount: C:\:/host or C:/:/host
	if len(spec) >= 3 && spec[1] == ':' && (spec[2] == '\\' || spec[2] == '/') {
		if idx := strings.IndexByte(spec[2:], ':'); idx >= 0 {
			return spec[:2+idx]
		}
		return spec
	}
	if host, _, ok := strings.Cut(spec, ":"); ok {
		return host
	}
	return spec
}

func anyToStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func mergeStringMap(dst map[string]string, src any) {
	m, ok := src.(map[string]any)
	if !ok {
		return
	}
	for k, v := range m {
		if s, ok := v.(string); ok {
			dst[k] = s
		}
	}
}

func findJSONKeyLine(rawText, key string) int {
	needle := `"` + key + `"`
	lines := strings.Split(rawText, "\n")
	for i, line := range lines {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 0
}
