package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/aloneangel45/mcpgate/pkg/audit"
	"github.com/aloneangel45/mcpgate/pkg/dlp"
	"github.com/aloneangel45/mcpgate/pkg/egress"
	"github.com/aloneangel45/mcpgate/pkg/mcpproxy"
	"github.com/aloneangel45/mcpgate/pkg/policy"
	"github.com/aloneangel45/mcpgate/pkg/preset"
	"github.com/aloneangel45/mcpgate/pkg/sandbox"
)

// dlpProxyAdapter bridges *dlp.Scanner to mcpproxy.PayloadScanner.
type dlpProxyAdapter struct {
	scanner *dlp.Scanner
}

func (a *dlpProxyAdapter) ScanPayload(text string) []mcpproxy.DLPFinding {
	if a == nil || a.scanner == nil {
		return nil
	}
	raw := a.scanner.Scan(text)
	if len(raw) == 0 {
		return nil
	}
	out := make([]mcpproxy.DLPFinding, len(raw))
	for i, f := range raw {
		out[i] = mcpproxy.DLPFinding{
			RuleID:       f.RuleID,
			Name:         f.Name,
			Severity:     f.Severity,
			MatchPreview: f.MatchPreview,
		}
	}
	return out
}

func (a *dlpProxyAdapter) RedactPayload(text string) (string, []mcpproxy.DLPFinding) {
	if a == nil || a.scanner == nil {
		return text, nil
	}
	redacted, raw := a.scanner.Redact(text)
	if len(raw) == 0 {
		return redacted, nil
	}
	out := make([]mcpproxy.DLPFinding, len(raw))
	for i, f := range raw {
		out[i] = mcpproxy.DLPFinding{
			RuleID:       f.RuleID,
			Name:         f.Name,
			Severity:     f.Severity,
			MatchPreview: f.MatchPreview,
		}
	}
	return redacted, out
}

// ============================================================================
// 1. mcpgate run
// ============================================================================

func newRunCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPath        string
		presetName        string
		serverName        string
		allowFS           []string
		denyFS            []string
		allowNet          []string
		denyNet           []string
		airgapped         bool
		inspectTLS        bool
		dlpAction         string
		noDotEnv          bool
		lockfilePath      string
		lockMode          string
		auditLogPath      string
		logAllowed        bool
		cleanEnv          bool
		noCleanEnv        bool
		passEnv           []string
		workDir           string
		maxCallsPerMin    int
		maxIdenticalCalls int
		nonInteractive    bool
	)

	cmd := &cobra.Command{
		Use:   "run [flags] -- <mcp-server-cmd...>",
		Short: "Run a local stdio MCP server inside the MCPGate zero-trust firewall & sandbox",
		Long:  "Wraps a local stdio MCP server with live JSON-RPC inspection, tool poisoning quarantine, SHA-256 schema lockfile verification, DLP scanning, SSRF-safe egress proxy, and OS process sandboxing. Stdout remains 100% pure JSON-RPC.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := loadPolicyWithPreset(policyPath, presetName)
			if err != nil {
				return err
			}

			// Apply CLI overrides cleanly.
			if len(allowFS) > 0 {
				pol.Filesystem.AllowPaths = append(pol.Filesystem.AllowPaths, allowFS...)
			}
			if len(denyFS) > 0 {
				pol.Filesystem.DenyPaths = append(pol.Filesystem.DenyPaths, denyFS...)
			}
			if len(allowNet) > 0 {
				pol.Network.AllowDomains = append(pol.Network.AllowDomains, allowNet...)
			}
			if len(denyNet) > 0 {
				pol.Network.DenyDomains = append(pol.Network.DenyDomains, denyNet...)
			}
			if airgapped {
				pol.Network.Enabled = false
			}
			if inspectTLS {
				pol.Network.InspectTLS = true
			}
			if cmd.Flags().Changed("dlp-action") {
				pol.DLP.Action = policy.Action(strings.ToLower(strings.TrimSpace(dlpAction)))
			}
			if noDotEnv {
				pol.DLP.LoadDotEnv = false
			}
			if cmd.Flags().Changed("lockfile") {
				pol.MCP.LockfilePath = lockfilePath
			}
			if cmd.Flags().Changed("lock-mode") {
				pol.MCP.LockMode = strings.ToLower(strings.TrimSpace(lockMode))
			}
			if cmd.Flags().Changed("audit-log") {
				pol.Audit.LogPath = auditLogPath
			}
			if cmd.Flags().Changed("log-allowed") {
				pol.Audit.LogAllowed = logAllowed
			}
			if cmd.Flags().Changed("clean-env") {
				pol.Sandbox.CleanEnv = cleanEnv
			}
			if noCleanEnv {
				pol.Sandbox.CleanEnv = false
			}
			if len(passEnv) > 0 {
				pol.Sandbox.PassEnv = append(pol.Sandbox.PassEnv, passEnv...)
			}
			if strings.TrimSpace(workDir) != "" {
				pol.Sandbox.WorkDir = workDir
			}
			if cmd.Flags().Changed("max-calls-per-min") {
				pol.MCP.MaxCallsPerMinute = maxCallsPerMin
			}
			if cmd.Flags().Changed("max-identical-calls") {
				pol.MCP.MaxIdenticalCalls = maxIdenticalCalls
			}

			if err := pol.Validate(); err != nil {
				return fmt.Errorf("invalid policy configuration: %w", err)
			}

			effWorkDir := strings.TrimSpace(pol.Sandbox.WorkDir)
			if effWorkDir == "" {
				if wd, wdErr := os.Getwd(); wdErr == nil {
					effWorkDir = wd
				}
			}

			effServer := strings.TrimSpace(serverName)
			if effServer == "" {
				effServer = "default"
			}
			sessionID := newSessionID()

			// Build DLP scanner.
			scanner, err := dlp.NewScanner(pol.DLP, effWorkDir)
			if err != nil {
				return fmt.Errorf("initialize DLP scanner: %w", err)
			}

			// Optional JSONL audit logger.
			var auditLogger *audit.Logger
			if strings.TrimSpace(pol.Audit.LogPath) != "" {
				auditLogger, err = audit.NewLogger(pol.Audit.LogPath)
				if err != nil {
					return fmt.Errorf("open audit log: %w", err)
				}
				defer func() {
					_ = auditLogger.Close()
				}()
			}

			var stderrMu sync.Mutex
			onEvent := func(ev policy.SecurityEvent) {
				if ev.Timestamp.IsZero() {
					ev.Timestamp = time.Now().UTC()
				}
				if ev.SessionID == "" {
					ev.SessionID = sessionID
				}
				if ev.Server == "" {
					ev.Server = effServer
				}
				if auditLogger != nil {
					_ = auditLogger.Log(ev)
				}
				if !strings.EqualFold(ev.Action, "allowed") {
					stderrMu.Lock()
					fmt.Fprintf(stderr, "[mcpgate] %s %s %s (%s): %s\n",
						strings.ToUpper(string(ev.Severity)),
						strings.ToUpper(ev.Action),
						ev.RuleID,
						ev.Category,
						ev.Message,
					)
					stderrMu.Unlock()
				}
			}

			// Always launch the local egress firewall proxy so even airgapped mode injects
			// HTTP_PROXY/HTTPS_PROXY returning 403 on all outbound requests.
			egressProxy, err := egress.New(egress.Options{
				Policy:     pol,
				Scanner:    scanner,
				ListenAddr: "127.0.0.1:0",
				SessionID:  sessionID,
				ServerName: effServer,
				OnEvent:    onEvent,
			})
			if err != nil {
				return fmt.Errorf("start egress firewall proxy: %w", err)
			}
			defer func() {
				_ = egressProxy.Close()
			}()

			extraEnv := envSliceToMap(egressProxy.EnvVars())

			baseCtx := cmd.Context()
			if baseCtx == nil {
				baseCtx = context.Background()
			}
			sigCtx, stopSignals := signal.NotifyContext(baseCtx, os.Interrupt, syscall.SIGTERM)
			defer stopSignals()

			// Prepare sandboxed child MCP server process.
			wc, err := sandbox.PrepareCommand(sigCtx, pol.Sandbox, args[0], args[1:], extraEnv)
			if err != nil {
				return fmt.Errorf("prepare sandboxed command: %w", err)
			}
			defer func() {
				_ = wc.Cleanup()
			}()

			childStdin, err := wc.Cmd.StdinPipe()
			if err != nil {
				return fmt.Errorf("create child stdin pipe: %w", err)
			}
			childStdout, err := wc.Cmd.StdoutPipe()
			if err != nil {
				return fmt.Errorf("create child stdout pipe: %w", err)
			}
			wc.Cmd.Stderr = stderr

			approver := buildApprover(nonInteractive, stderr, &stderrMu)

			proxy, err := mcpproxy.NewProxy(mcpproxy.Options{
				Policy:     pol,
				ServerName: effServer,
				WorkDir:    effWorkDir,
				SessionID:  sessionID,
				Scanner:    &dlpProxyAdapter{scanner: scanner},
				Approver:   approver,
				OnEvent:    onEvent,
			})
			if err != nil {
				return fmt.Errorf("initialize MCP proxy: %w", err)
			}

			if err := wc.Start(); err != nil {
				return fmt.Errorf("start MCP server %q: %w", args[0], err)
			}

			proxyErr := proxy.Run(sigCtx, stdin, stdout, childStdin, childStdout)

			_ = childStdin.Close()

			// Wait briefly for graceful child exit; otherwise terminate process tree via Job/PGID.
			waitCh := make(chan error, 1)
			go func() {
				waitCh <- wc.Wait()
			}()

			var waitErr error
			if sigCtx.Err() != nil {
				_ = wc.Kill()
				select {
				case waitErr = <-waitCh:
				case <-time.After(2 * time.Second):
				}
			} else {
				select {
				case waitErr = <-waitCh:
				case <-time.After(3 * time.Second):
					_ = wc.Kill()
					select {
					case waitErr = <-waitCh:
					case <-time.After(2 * time.Second):
					}
				}
			}

			_ = wc.Cleanup()
			_ = egressProxy.Close()
			if auditLogger != nil {
				_ = auditLogger.Sync()
				_ = auditLogger.Close()
			}

			if errors.Is(proxyErr, context.Canceled) || sigCtx.Err() != nil {
				return nil
			}
			if proxyErr != nil {
				return proxyErr
			}
			// Propagate non-zero exit code only if child exited abnormally without clean EOF.
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) && exitErr.ExitCode() > 0 {
				return &exitError{code: exitErr.ExitCode()}
			}
			return nil
		},
	}

	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to mcpgate.yaml policy file")
	cmd.Flags().StringVar(&presetName, "preset", "balanced", "Built-in policy preset: strict, balanced, readonly, airgapped")
	cmd.Flags().StringVar(&serverName, "server", "default", "Logical MCP server name (used in lockfile & audit events)")
	cmd.Flags().StringArrayVar(&allowFS, "allow-fs", nil, "Allowlisted filesystem root path (repeatable)")
	cmd.Flags().StringArrayVar(&denyFS, "deny-fs", nil, "Denied filesystem path or glob (repeatable)")
	cmd.Flags().StringArrayVar(&allowNet, "allow-net", nil, "Allowlisted outbound domain or wildcard (repeatable)")
	cmd.Flags().StringArrayVar(&denyNet, "deny-net", nil, "Denied outbound domain or wildcard (repeatable)")
	cmd.Flags().BoolVar(&airgapped, "airgapped", false, "Disable all outbound network access (403 on every request)")
	cmd.Flags().BoolVar(&inspectTLS, "inspect-tls", false, "Enable ephemeral local MITM CA for HTTPS DLP inspection")
	cmd.Flags().StringVar(&dlpAction, "dlp-action", "", "DLP action on secret match: block, redact, warn")
	cmd.Flags().BoolVar(&noDotEnv, "no-dotenv", false, "Disable automatic .env secret fingerprinting")
	cmd.Flags().StringVar(&lockfilePath, "lockfile", "", "Path to mcpgate.lock SHA-256 tool lockfile")
	cmd.Flags().StringVar(&lockMode, "lock-mode", "", "Schema lockfile mode: off, warn, enforce, update")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "", "Path to JSONL security audit log file")
	cmd.Flags().BoolVar(&logAllowed, "log-allowed", false, "Also log allowed tool calls and egress requests")
	cmd.Flags().BoolVar(&cleanEnv, "clean-env", true, "Strip host environment secrets before launching child process")
	cmd.Flags().BoolVar(&noCleanEnv, "no-clean-env", false, "Disable environment stripping and inherit host environment")
	cmd.Flags().StringArrayVar(&passEnv, "pass-env", nil, "Additional environment variable key to pass through when clean-env is active (repeatable)")
	cmd.Flags().StringVar(&workDir, "work-dir", "", "Working directory for child process and path/dotenv resolution")
	cmd.Flags().IntVar(&maxCallsPerMin, "max-calls-per-min", 0, "Circuit breaker: max tool calls per minute (0 = policy default)")
	cmd.Flags().IntVar(&maxIdenticalCalls, "max-identical-calls", 0, "Circuit breaker: max consecutive identical tool calls (0 = policy default)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Never prompt on TTY for ActionPrompt tools (fail closed)")

	return cmd
}

func buildApprover(nonInteractive bool, stderr io.Writer, mu *sync.Mutex) mcpproxy.ApproverFunc {
	if nonInteractive {
		return func(tool string, args map[string]any, reason string) bool {
			return false
		}
	}
	return func(tool string, args map[string]any, reason string) bool {
		// Never read os.Stdin (it carries JSON-RPC frames). Open controlling TTY if available.
		ttyPath := "/dev/tty"
		if runtime.GOOS == "windows" {
			ttyPath = "CONIN$"
		}
		tty, err := os.Open(ttyPath)
		if err != nil {
			// Headless / non-TTY environment: fail closed safely.
			return false
		}
		defer tty.Close()

		mu.Lock()
		fmt.Fprintf(stderr, "[mcpgate] APPROVAL REQUIRED for tool %q (%s). Allow once? [y/N]: ", tool, reason)
		mu.Unlock()

		br := bufio.NewReader(tty)
		line, err := br.ReadString('\n')
		if err != nil && len(line) == 0 {
			return false
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		return ans == "y" || ans == "yes"
	}
}

// ============================================================================
// 2. mcpgate audit
// ============================================================================

func newAuditCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		allIDEs bool
		format  string
		outPath string
		failOn  string
	)

	cmd := &cobra.Command{
		Use:   "audit [<config|dir>...] [flags]",
		Short: "Audit IDE MCP configurations and mcpgate.yaml policies for OWASP MCP Top 10 risks",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtNorm := strings.ToLower(strings.TrimSpace(format))
			switch fmtNorm {
			case "table", "json", "sarif", "html":
			default:
				return fmt.Errorf("invalid --format %q (expected table, json, sarif, or html)", format)
			}

			failRank, err := parseSeverityThreshold(failOn)
			if err != nil {
				return err
			}

			if !allIDEs && len(args) == 0 {
				return fmt.Errorf("specify at least one config file or directory, or pass --all-ides")
			}

			targets, err := collectAuditTargets(args, allIDEs)
			if err != nil {
				return err
			}

			report, err := audit.AuditFiles(targets)
			if err != nil {
				return err
			}

			var rendered []byte
			switch fmtNorm {
			case "json":
				b, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				rendered = append(b, '\n')
			case "sarif":
				b, err := audit.ExportSARIFReport(report)
				if err != nil {
					return err
				}
				rendered = b
			case "html":
				h, err := audit.RenderAuditHTML(report)
				if err != nil {
					return err
				}
				rendered = []byte(h)
			case "table":
				rendered = []byte(formatAuditTable(report))
			}

			if strings.TrimSpace(outPath) != "" {
				if err := writeOutputFile(outPath, rendered); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "Audit report (%s) written to %s (grade=%s, risk=%d/100, findings=%d)\n",
					fmtNorm, outPath, report.Grade, report.RiskScore, len(report.Findings))
			} else {
				if _, err := stdout.Write(rendered); err != nil {
					return err
				}
			}

			if failRank > 0 {
				for _, f := range report.Findings {
					if severityLevelRank(f.Severity) >= failRank {
						return &exitError{
							code: 1,
							msg:  fmt.Sprintf("audit failed: finding %s (%s) meets or exceeds --fail-on=%s", f.RuleID, f.Severity, failOn),
						}
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&allIDEs, "all-ides", false, "Discover and audit all installed IDE MCP configurations")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, sarif, html")
	cmd.Flags().StringVar(&outPath, "out", "", "Write rendered report to file path")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "Exit non-zero if any finding meets/exceeds severity: critical, high, medium, low, none")

	return cmd
}

func collectAuditTargets(args []string, allIDEs bool) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	add := func(p string) {
		clean := filepath.Clean(p)
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}

	if allIDEs {
		for _, cfg := range preset.DiscoverIDEConfigs() {
			add(cfg.Path)
		}
	}

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("stat audit target %q: %w", arg, err)
		}
		if !info.IsDir() {
			add(arg)
			continue
		}

		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == ".next" || name == "dist" {
					return filepath.SkipDir
				}
				return nil
			}
			if isCandidateAuditFile(path) {
				add(path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan directory %q: %w", arg, err)
		}
	}
	return out, nil
}

func isCandidateAuditFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	switch ext {
	case ".json", ".jsonc":
		if strings.Contains(base, "mcp") || strings.Contains(base, "claude") {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 2*1024*1024 {
			return false
		}
		s := string(data)
		return strings.Contains(s, `"mcpServers"`) || strings.Contains(s, `"servers"`) || strings.Contains(s, `"context_servers"`)
	case ".yaml", ".yml":
		if strings.Contains(base, "mcpgate") {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 512*1024 {
			return false
		}
		return strings.Contains(string(data), policy.CurrentVersion)
	default:
		return false
	}
}

func formatAuditTable(r *audit.AuditReport) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "MCPGate Security Audit Report\n")
	fmt.Fprintf(&buf, "Grade: %s | Risk Score: %d/100 | Files: %d | Servers: %d | Findings: %d\n",
		r.Grade, r.RiskScore, len(r.ScannedFiles), r.ServersChecked, len(r.Findings))
	fmt.Fprintf(&buf, "Severity: critical=%d high=%d medium=%d low=%d info=%d\n\n",
		r.CountsBySeverity[policy.SeverityCritical],
		r.CountsBySeverity[policy.SeverityHigh],
		r.CountsBySeverity[policy.SeverityMedium],
		r.CountsBySeverity[policy.SeverityLow],
		r.CountsBySeverity[policy.SeverityInfo],
	)

	if len(r.Findings) == 0 {
		fmt.Fprintf(&buf, "No security issues found.\n")
		return buf.String()
	}

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tSERVER\tLOCATION\tMESSAGE")
	fmt.Fprintln(tw, "--------\t----\t------\t--------\t-------")
	for _, f := range r.Findings {
		loc := filepath.Base(f.File)
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		srv := f.Server
		if srv == "" {
			srv = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(f.Severity)),
			f.RuleID,
			srv,
			loc,
			f.Message,
		)
	}
	_ = tw.Flush()
	return buf.String()
}

// ============================================================================
// 3. mcpgate lock <init|verify|update>
// ============================================================================

func newLockCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		lockfilePath string
		serverName   string
		schemaFile   string
		timeout      time.Duration
	)

	lockCmd := &cobra.Command{
		Use:   "lock",
		Short: "Pin and verify MCP tool schemas via canonical SHA-256 lockfiles (mcpgate.lock)",
	}
	lockCmd.PersistentFlags().StringVar(&lockfilePath, "lockfile", "mcpgate.lock", "Path to mcpgate.lock file")
	lockCmd.PersistentFlags().StringVar(&serverName, "server", "default", "Logical server name inside lockfile")
	lockCmd.PersistentFlags().StringVar(&schemaFile, "schema-file", "", "Load tools JSON file instead of spawning an MCP server")
	lockCmd.PersistentFlags().DurationVar(&timeout, "timeout", 15*time.Second, "Timeout when probing a live stdio MCP server")

	runLockAction := func(action string) func(cmd *cobra.Command, args []string) error {
		return func(cmd *cobra.Command, args []string) error {
			var (
				tools []mcpproxy.ToolDefinition
				err   error
			)
			if strings.TrimSpace(schemaFile) != "" {
				tools, err = loadToolsFromSchemaFile(schemaFile)
			} else {
				if len(args) == 0 {
					return fmt.Errorf("provide --schema-file <path> or -- <mcp-server-cmd...>")
				}
				ctx := cmd.Context()
				if ctx == nil {
					ctx = context.Background()
				}
				tools, err = probeMCPServerTools(ctx, args, timeout, stderr)
			}
			if err != nil {
				return err
			}

			srv := strings.TrimSpace(serverName)
			if srv == "" {
				srv = "default"
			}

			switch action {
			case "init", "update":
				lf, err := mcpproxy.LoadOrCreateLockfile(lockfilePath)
				if err != nil {
					return err
				}
				lf.LockTools(srv, tools)
				if err := lf.SaveTo(lockfilePath); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "Locked %d tool(s) for server %q in %s\n", len(tools), srv, lockfilePath)
				tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "TOOL\tSHA256")
				for _, t := range tools {
					h := mcpproxy.ComputeToolHash(t)
					fmt.Fprintf(tw, "%s\t%s\n", t.Name, h[:16])
				}
				_ = tw.Flush()
				return nil

			case "verify":
				lf, err := mcpproxy.LoadLockfile(lockfilePath)
				if err != nil {
					return err
				}
				if _, ok := lf.Servers[srv]; !ok {
					return &exitError{
						code: 1,
						msg:  fmt.Sprintf("lock verify failed: server %q is not pinned in %s", srv, lockfilePath),
					}
				}
				violations := lf.VerifyTools(srv, tools, "enforce")
				if len(violations) > 0 {
					tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
					fmt.Fprintln(tw, "RULE\tKIND\tTOOL\tMESSAGE")
					for _, v := range violations {
						fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", v.RuleID, v.Kind, v.ToolName, v.Message)
					}
					_ = tw.Flush()
					return &exitError{
						code: 1,
						msg:  fmt.Sprintf("lock verify failed: %d schema violation(s) detected for server %q", len(violations), srv),
					}
				}
				fmt.Fprintf(stdout, "OK: verified %d tool(s) for server %q against %s\n", len(tools), srv, lockfilePath)
				return nil

			default:
				return fmt.Errorf("unknown lock action %q", action)
			}
		}
	}

	initCmd := &cobra.Command{
		Use:   "init [flags] [-- <mcp-server-cmd...>]",
		Short: "Initialize or pin tool SHA-256 hashes into mcpgate.lock",
		RunE:  runLockAction("init"),
	}
	initCmd.Flags().SetInterspersed(false)

	verifyCmd := &cobra.Command{
		Use:   "verify [flags] [-- <mcp-server-cmd...>]",
		Short: "Verify tool definitions against pinned SHA-256 hashes in mcpgate.lock",
		RunE:  runLockAction("verify"),
	}
	verifyCmd.Flags().SetInterspersed(false)

	updateCmd := &cobra.Command{
		Use:   "update [flags] [-- <mcp-server-cmd...>]",
		Short: "Update pinned tool SHA-256 hashes in mcpgate.lock",
		RunE:  runLockAction("update"),
	}
	updateCmd.Flags().SetInterspersed(false)

	lockCmd.AddCommand(initCmd, verifyCmd, updateCmd)
	return lockCmd
}

func loadToolsFromSchemaFile(path string) ([]mcpproxy.ToolDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema file %q: %w", path, err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("schema file %q is empty", path)
	}

	// Format 1: []ToolDefinition
	if trimmed[0] == '[' {
		var list []mcpproxy.ToolDefinition
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("parse schema array %q: %w", path, err)
		}
		return list, nil
	}

	// Format 2: {"tools": [...]} or JSON-RPC {"result": {"tools": [...]}}
	var obj struct {
		Tools  []mcpproxy.ToolDefinition `json:"tools"`
		Result *struct {
			Tools []mcpproxy.ToolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, fmt.Errorf("parse schema object %q: %w", path, err)
	}
	if obj.Result != nil {
		return obj.Result.Tools, nil
	}
	if obj.Tools != nil {
		return obj.Tools, nil
	}
	return []mcpproxy.ToolDefinition{}, nil
}

func probeMCPServerTools(ctx context.Context, cmdArgs []string, timeout time.Duration, stderr io.Writer) ([]mcpproxy.ToolDefinition, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(pctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stderr = stderr
	inPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdin pipe: %w", err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn MCP server %q: %w", cmdArgs[0], err)
	}
	defer func() {
		_ = inPipe.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	br := bufio.NewReaderSize(outPipe, 64*1024)

	// 1. initialize
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "mcpgate",
				"version": Version,
			},
		},
	}
	if err := writeNDJSONMessage(inPipe, initReq); err != nil {
		return nil, fmt.Errorf("send initialize: %w", err)
	}
	if _, err := waitRPCResponse(pctx, br, "1"); err != nil {
		return nil, fmt.Errorf("wait initialize response: %w", err)
	}

	// 2. notifications/initialized
	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	if err := writeNDJSONMessage(inPipe, notif); err != nil {
		return nil, fmt.Errorf("send notifications/initialized: %w", err)
	}

	// 3. tools/list
	listReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	if err := writeNDJSONMessage(inPipe, listReq); err != nil {
		return nil, fmt.Errorf("send tools/list: %w", err)
	}
	rawResp, err := waitRPCResponse(pctx, br, "2")
	if err != nil {
		return nil, fmt.Errorf("wait tools/list response: %w", err)
	}

	var parsed struct {
		Result struct {
			Tools []mcpproxy.ToolDefinition `json:"tools"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rawResp, &parsed); err != nil {
		return nil, fmt.Errorf("decode tools/list response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("MCP server returned error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	return parsed.Result.Tools, nil
}

func waitRPCResponse(ctx context.Context, br *bufio.Reader, expectedID string) ([]byte, error) {
	type readRes struct {
		raw []byte
		err error
	}
	for {
		ch := make(chan readRes, 1)
		go func() {
			raw, _, err := readJSONRPCFrame(br)
			ch <- readRes{raw: raw, err: err}
		}()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-ch:
			if r.err != nil {
				return nil, r.err
			}
			var env struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(r.raw, &env) != nil {
				continue
			}
			idStr := strings.TrimSpace(string(env.ID))
			if idStr == expectedID || idStr == strconv.Quote(expectedID) {
				return r.raw, nil
			}
		}
	}
}

func writeNDJSONMessage(w io.Writer, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// ============================================================================
// 4. mcpgate test-policy
// ============================================================================

type policyCheckResult struct {
	Check    string          `json:"check"`
	Target   string          `json:"target"`
	Action   policy.Action   `json:"action"`
	Allowed  bool            `json:"allowed"`
	RuleID   string          `json:"rule_id"`
	Severity policy.Severity `json:"severity"`
	Reason   string          `json:"reason"`
}

type policyEvalReport struct {
	Policy  string              `json:"policy"`
	Preset  string              `json:"preset,omitempty"`
	Passed  bool                `json:"passed"`
	Checks  []policyCheckResult `json:"checks"`
}

type policyEvalInput struct {
	PolicyPath string
	Preset     string
	WorkDir    string
	Tool       string
	Args       []string
	Paths      []string
	URL        string
	Payload    string
}

func evaluatePolicyInput(in policyEvalInput) (*policyEvalReport, error) {
	pol, err := loadPolicyWithPreset(in.PolicyPath, in.Preset)
	if err != nil {
		return nil, err
	}
	workDir := strings.TrimSpace(in.WorkDir)
	if workDir == "" {
		workDir = pol.Sandbox.WorkDir
	}
	if workDir == "" {
		if wd, wdErr := os.Getwd(); wdErr == nil {
			workDir = wd
		}
	}

	scanner, err := dlp.NewScanner(pol.DLP, workDir)
	if err != nil {
		return nil, fmt.Errorf("init DLP scanner: %w", err)
	}

	report := &policyEvalReport{
		Policy: pol.Name,
		Preset: pol.Preset,
		Passed: true,
		Checks: []policyCheckResult{},
	}

	record := func(res policyCheckResult) {
		if !res.Allowed {
			report.Passed = false
		}
		report.Checks = append(report.Checks, res)
	}

	// 1. Tool evaluation.
	if strings.TrimSpace(in.Tool) != "" {
		dec := pol.EvaluateTool(in.Tool)
		allowed := dec.Action != policy.ActionDeny && dec.Action != policy.ActionBlock
		record(policyCheckResult{
			Check:    "tool",
			Target:   in.Tool,
			Action:   dec.Action,
			Allowed:  allowed,
			RuleID:   dec.RuleID,
			Severity: dec.Severity,
			Reason:   dec.Reason,
		})
	}

	// 2. Key=Value tool args -> path extraction + DLP scan.
	if len(in.Args) > 0 {
		argMap := make(map[string]any, len(in.Args))
		for _, kv := range in.Args {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("invalid --arg %q (expected key=value)", kv)
			}
			argMap[strings.TrimSpace(k)] = v
		}
		for _, extractedPath := range mcpproxy.ExtractPaths(argMap) {
			dec := pol.EvaluatePath(extractedPath, workDir)
			record(policyCheckResult{
				Check:    "arg_path",
				Target:   extractedPath,
				Action:   dec.Action,
				Allowed:  dec.Action != policy.ActionDeny && dec.Action != policy.ActionBlock,
				RuleID:   dec.RuleID,
				Severity: dec.Severity,
				Reason:   dec.Reason,
			})
		}
		if pol.DLP.Enabled {
			keys := make([]string, 0, len(argMap))
			for k := range argMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v, _ := argMap[k].(string)
				findings := scanner.Scan(v)
				if len(findings) > 0 {
					act := pol.DLP.Action
					if act == "" {
						act = policy.ActionBlock
					}
					record(policyCheckResult{
						Check:    "arg_dlp",
						Target:   fmt.Sprintf("arg.%s (%s)", k, findings[0].MatchPreview),
						Action:   act,
						Allowed:  act != policy.ActionBlock && act != policy.ActionDeny,
						RuleID:   findings[0].RuleID,
						Severity: findings[0].Severity,
						Reason:   fmt.Sprintf("detected %d secret finding(s): %s", len(findings), findings[0].Name),
					})
				}
			}
		}
	}

	// 3. Explicit filesystem paths.
	for _, p := range in.Paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		dec := pol.EvaluatePath(p, workDir)
		record(policyCheckResult{
			Check:    "path",
			Target:   p,
			Action:   dec.Action,
			Allowed:  dec.Action != policy.ActionDeny && dec.Action != policy.ActionBlock,
			RuleID:   dec.RuleID,
			Severity: dec.Severity,
			Reason:   dec.Reason,
		})
	}

	// 4. URL / domain / SSRF check.
	if strings.TrimSpace(in.URL) != "" {
		rawURL := strings.TrimSpace(in.URL)
		parseTarget := rawURL
		if !strings.Contains(parseTarget, "://") {
			parseTarget = "https://" + parseTarget
		}
		u, err := url.Parse(parseTarget)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid --url %q", rawURL)
		}
		host := u.Hostname()
		port := 443
		if strings.EqualFold(u.Scheme, "http") {
			port = 80
		}
		if ps := u.Port(); ps != "" {
			if n, convErr := strconv.Atoi(ps); convErr == nil {
				port = n
			}
		}

		// Domain/port/airgapped check.
		domDec := pol.EvaluateDomain(host, port)
		record(policyCheckResult{
			Check:    "egress_domain",
			Target:   fmt.Sprintf("%s:%d", host, port),
			Action:   domDec.Action,
			Allowed:  domDec.Action == policy.ActionAllow,
			RuleID:   domDec.RuleID,
			Severity: domDec.Severity,
			Reason:   domDec.Reason,
		})

		// SSRF host & IP check.
		ssrfBlocked := false
		if blocked, ruleID, reason := egress.ValidateTargetHost(host, pol.Network); blocked {
			ssrfBlocked = true
			sev := policy.SeverityHigh
			if ruleID == "MCP04-SSRF-METADATA" {
				sev = policy.SeverityCritical
			}
			record(policyCheckResult{
				Check:    "ssrf",
				Target:   host,
				Action:   policy.ActionDeny,
				Allowed:  false,
				RuleID:   ruleID,
				Severity: sev,
				Reason:   reason,
			})
		}

		if !ssrfBlocked {
			if ip := net.ParseIP(host); ip != nil {
				if blocked, ruleID, reason := egress.ValidateTargetIP(ip, pol.Network); blocked {
					ssrfBlocked = true
					sev := policy.SeverityHigh
					if ruleID == "MCP04-SSRF-METADATA" {
						sev = policy.SeverityCritical
					}
					record(policyCheckResult{
						Check:    "ssrf",
						Target:   ip.String(),
						Action:   policy.ActionDeny,
						Allowed:  false,
						RuleID:   ruleID,
						Severity: sev,
						Reason:   reason,
					})
				}
			} else if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
				if blocked, ruleID, reason := egress.ValidateTargetIP(net.ParseIP("127.0.0.1"), pol.Network); blocked {
					ssrfBlocked = true
					record(policyCheckResult{
						Check:    "ssrf",
						Target:   host,
						Action:   policy.ActionDeny,
						Allowed:  false,
						RuleID:   ruleID,
						Severity: policy.SeverityHigh,
						Reason:   reason,
					})
				}
			} else {
				// Best-effort DNS lookup with short timeout so offline runs still succeed cleanly.
				lookupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				addrs, lookupErr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
				cancel()
				if lookupErr == nil {
					for _, a := range addrs {
						if blocked, ruleID, reason := egress.ValidateTargetIP(a.IP, pol.Network); blocked {
							ssrfBlocked = true
							sev := policy.SeverityHigh
							if ruleID == "MCP04-SSRF-METADATA" {
								sev = policy.SeverityCritical
							}
							record(policyCheckResult{
								Check:    "ssrf",
								Target:   fmt.Sprintf("%s -> %s", host, a.IP.String()),
								Action:   policy.ActionDeny,
								Allowed:  false,
								RuleID:   ruleID,
								Severity: sev,
								Reason:   reason,
							})
							break
						}
					}
				}
			}
		}

		if !ssrfBlocked {
			record(policyCheckResult{
				Check:    "ssrf",
				Target:   host,
				Action:   policy.ActionAllow,
				Allowed:  true,
				RuleID:   "MCP04-SSRF-OK",
				Severity: policy.SeverityInfo,
				Reason:   "target passed SSRF host/IP checks",
			})
		}
	}

	// 5. DLP payload scan.
	if in.Payload != "" {
		if !pol.DLP.Enabled {
			record(policyCheckResult{
				Check:    "dlp",
				Target:   "<payload>",
				Action:   policy.ActionAllow,
				Allowed:  true,
				RuleID:   "MCP03-DLP-DISABLED",
				Severity: policy.SeverityInfo,
				Reason:   "DLP scanning is disabled by policy",
			})
		} else {
			findings := scanner.Scan(in.Payload)
			if len(findings) == 0 {
				record(policyCheckResult{
					Check:    "dlp",
					Target:   "<payload>",
					Action:   policy.ActionAllow,
					Allowed:  true,
					RuleID:   "MCP03-DLP-CLEAN",
					Severity: policy.SeverityInfo,
					Reason:   "no secrets or PII detected",
				})
			} else {
				act := pol.DLP.Action
				if act == "" {
					act = policy.ActionBlock
				}
				for _, f := range findings {
					record(policyCheckResult{
						Check:    "dlp",
						Target:   f.MatchPreview,
						Action:   act,
						Allowed:  act != policy.ActionBlock && act != policy.ActionDeny,
						RuleID:   f.RuleID,
						Severity: f.Severity,
						Reason:   fmt.Sprintf("%s detected (preview=%s, sha256=%s)", f.Name, f.MatchPreview, f.SHA256Prefix),
					})
				}
			}
		}
	}

	if len(report.Checks) == 0 {
		return nil, fmt.Errorf("specify at least one check flag: --tool, --arg, --path, --url, or --payload")
	}

	return report, nil
}

func newTestPolicyCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPath string
		presetName string
		workDir    string
		toolName   string
		argPairs   []string
		paths      []string
		targetURL  string
		payload    string
		asJSON     bool
	)

	cmd := &cobra.Command{
		Use:   "test-policy [flags]",
		Short: "Dry-run policy evaluation for tools, paths, URLs/SSRF, and DLP payloads",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := evaluatePolicyInput(policyEvalInput{
				PolicyPath: policyPath,
				Preset:     presetName,
				WorkDir:    workDir,
				Tool:       toolName,
				Args:       argPairs,
				Paths:      paths,
				URL:        targetURL,
				Payload:    payload,
			})
			if err != nil {
				return err
			}

			if asJSON {
				if err := writeIndentedJSON(stdout, report); err != nil {
					return err
				}
			} else {
				status := "PASS"
				if !report.Passed {
					status = "DENY"
				}
				fmt.Fprintf(stdout, "Policy Evaluation: %s (policy=%s)\n\n", status, report.Policy)
				tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "CHECK\tRESULT\tRULE\tTARGET\tREASON")
				fmt.Fprintln(tw, "-----\t------\t----\t------\t------")
				for _, c := range report.Checks {
					badge := strings.ToUpper(string(c.Action))
					if c.Allowed && c.Action == policy.ActionAllow {
						badge = "PASS"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.Check, badge, c.RuleID, c.Target, c.Reason)
				}
				_ = tw.Flush()
			}

			if !report.Passed {
				return &exitError{code: 1}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to mcpgate.yaml policy file")
	cmd.Flags().StringVar(&presetName, "preset", "balanced", "Built-in policy preset: strict, balanced, readonly, airgapped")
	cmd.Flags().StringVar(&workDir, "work-dir", "", "Working directory for relative path and .env resolution")
	cmd.Flags().StringVar(&toolName, "tool", "", "MCP tool name to evaluate")
	cmd.Flags().StringArrayVar(&argPairs, "arg", nil, "Tool argument in key=value format (repeatable)")
	cmd.Flags().StringArrayVar(&paths, "path", nil, "Filesystem path to evaluate (repeatable)")
	cmd.Flags().StringVar(&targetURL, "url", "", "Outbound URL or host to evaluate for egress & SSRF")
	cmd.Flags().StringVar(&payload, "payload", "", "Text payload to scan with DLP engine")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output structured JSON")

	return cmd
}

// ============================================================================
// 5. mcpgate inspect <audit.jsonl>
// ============================================================================

func newInspectCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		asJSON    bool
		sarifPath string
		htmlPath  string
		category  string
		severity  string
	)

	cmd := &cobra.Command{
		Use:   "inspect <audit.jsonl> [flags]",
		Short: "Inspect, filter, summarize, and export runtime JSONL audit telemetry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			events, err := audit.LoadEvents(args[0])
			if err != nil {
				return err
			}

			filtered := filterSecurityEvents(events, category, severity)
			summary := audit.Summarize(filtered)

			if strings.TrimSpace(sarifPath) != "" {
				sarifBytes, err := audit.ExportSARIFEvents(filtered)
				if err != nil {
					return err
				}
				if err := writeOutputFile(sarifPath, sarifBytes); err != nil {
					return err
				}
			}
			if strings.TrimSpace(htmlPath) != "" {
				if err := audit.WriteEventsHTML(htmlPath, filtered, "MCPGate Runtime Security Session Report"); err != nil {
					return err
				}
			}

			if asJSON {
				payload := map[string]any{
					"summary": summary,
					"events":  filtered,
				}
				if sarifPath != "" {
					payload["sarif_path"] = sarifPath
				}
				if htmlPath != "" {
					payload["html_path"] = htmlPath
				}
				return writeIndentedJSON(stdout, payload)
			}

			fmt.Fprintf(stdout, "MCPGate Audit Log Summary (%s)\n", args[0])
			fmt.Fprintf(stdout, "Total Events: %d\n", summary.TotalEvents)
			if !summary.FirstEvent.IsZero() {
				fmt.Fprintf(stdout, "Time Window:  %s -> %s\n",
					summary.FirstEvent.UTC().Format(time.RFC3339),
					summary.LastEvent.UTC().Format(time.RFC3339),
				)
			}
			fmt.Fprintf(stdout, "By Severity:  critical=%d high=%d medium=%d low=%d info=%d\n",
				summary.BySeverity[policy.SeverityCritical],
				summary.BySeverity[policy.SeverityHigh],
				summary.BySeverity[policy.SeverityMedium],
				summary.BySeverity[policy.SeverityLow],
				summary.BySeverity[policy.SeverityInfo],
			)

			if len(summary.ByCategory) > 0 {
				fmt.Fprintf(stdout, "By Category:  %s\n", formatCountMap(summary.ByCategory))
			}
			if len(summary.ByAction) > 0 {
				fmt.Fprintf(stdout, "By Action:    %s\n", formatCountMap(summary.ByAction))
			}
			if len(summary.ByRuleID) > 0 {
				fmt.Fprintf(stdout, "By Rule ID:   %s\n", formatCountMap(summary.ByRuleID))
			}
			if len(summary.TopBlockedTools) > 0 {
				fmt.Fprintf(stdout, "\nTop Blocked Tools:\n")
				for _, tc := range summary.TopBlockedTools {
					fmt.Fprintf(stdout, "  - %s (%d)\n", tc.Name, tc.Count)
				}
			}
			if len(summary.TopBlockedTargets) > 0 {
				fmt.Fprintf(stdout, "\nTop Blocked Targets:\n")
				for _, tc := range summary.TopBlockedTargets {
					fmt.Fprintf(stdout, "  - %s (%d)\n", tc.Name, tc.Count)
				}
			}
			if sarifPath != "" {
				fmt.Fprintf(stdout, "\nSARIF 2.1.0 written to: %s\n", sarifPath)
			}
			if htmlPath != "" {
				fmt.Fprintf(stdout, "HTML report written to: %s\n", htmlPath)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output summary and filtered events as JSON")
	cmd.Flags().StringVar(&sarifPath, "sarif", "", "Export events as SARIF 2.1.0 to path")
	cmd.Flags().StringVar(&htmlPath, "html", "", "Export events as self-contained dark HTML report to path")
	cmd.Flags().StringVar(&category, "category", "", "Filter events by category (e.g. dlp, poisoning, path, rugpull, breaker, egress, ssrf)")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter events by severity (critical, high, medium, low, info)")

	return cmd
}

func filterSecurityEvents(events []policy.SecurityEvent, category, severity string) []policy.SecurityEvent {
	cat := strings.ToLower(strings.TrimSpace(category))
	sev := strings.ToLower(strings.TrimSpace(severity))
	if cat == "" && sev == "" {
		if events == nil {
			return []policy.SecurityEvent{}
		}
		return events
	}
	out := make([]policy.SecurityEvent, 0, len(events))
	for _, ev := range events {
		if cat != "" && strings.ToLower(strings.TrimSpace(ev.Category)) != cat {
			continue
		}
		if sev != "" && strings.ToLower(strings.TrimSpace(string(ev.Severity))) != sev {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// ============================================================================
// 6. mcpgate doctor
// ============================================================================

type doctorReport struct {
	Version        string                   `json:"version"`
	ReadinessGrade string                   `json:"readiness_grade"`
	Capabilities   sandbox.HostCapabilities `json:"capabilities"`
	IDEConfigs     []preset.IDEConfig       `json:"ide_configs"`
	PolicyCheck    *doctorCheckStatus       `json:"policy_check,omitempty"`
	LockfileCheck  *doctorCheckStatus       `json:"lockfile_check,omitempty"`
	Notes          []string                 `json:"notes,omitempty"`
}

type doctorCheckStatus struct {
	Path    string `json:"path"`
	Valid   bool   `json:"valid"`
	Summary string `json:"summary"`
}

func newDoctorCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		asJSON       bool
		policyPath   string
		lockfilePath string
	)

	cmd := &cobra.Command{
		Use:   "doctor [flags]",
		Short: "Diagnose host sandbox capabilities, discovered IDE configs, and policy/lockfile health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			caps := sandbox.Capabilities()
			discovered := preset.DiscoverIDEConfigs()

			rep := doctorReport{
				Version:      Version,
				Capabilities: caps,
				IDEConfigs:   discovered,
			}

			score := 100
			if !caps.CleanEnvSupported {
				score -= 20
				rep.Notes = append(rep.Notes, "clean environment isolation not supported")
			}
			if caps.ProcessIsolation == "" || strings.EqualFold(caps.ProcessIsolation, "none") {
				score -= 20
				rep.Notes = append(rep.Notes, "OS process-tree isolation unavailable")
			}
			if strings.Contains(strings.ToLower(caps.FilesystemJail), "none") || strings.Contains(strings.ToLower(caps.FilesystemJail), "proxy") {
				// Non-fatal on platforms without kernel FS jail (Windows relies on proxy path confinement + Win32 Job Object).
				score -= 5
			}

			if strings.TrimSpace(policyPath) != "" {
				pol, err := policy.LoadFile(policyPath)
				if err != nil {
					score -= 35
					rep.PolicyCheck = &doctorCheckStatus{
						Path:    policyPath,
						Valid:   false,
						Summary: err.Error(),
					}
				} else {
					summary := fmt.Sprintf("valid (preset=%s, dlp=%v/%s, net=%v, lock_mode=%s)",
						pol.Preset, pol.DLP.Enabled, pol.DLP.Action, pol.Network.Enabled, pol.MCP.LockMode)
					if auditRep, aErr := audit.AuditFile(policyPath); aErr == nil && len(auditRep.Findings) > 0 {
						summary += fmt.Sprintf(", %d policy audit finding(s)", len(auditRep.Findings))
						score -= 10
					}
					rep.PolicyCheck = &doctorCheckStatus{
						Path:    policyPath,
						Valid:   true,
						Summary: summary,
					}
				}
			}

			if strings.TrimSpace(lockfilePath) != "" {
				lf, err := mcpproxy.LoadLockfile(lockfilePath)
				if err != nil {
					score -= 30
					rep.LockfileCheck = &doctorCheckStatus{
						Path:    lockfilePath,
						Valid:   false,
						Summary: err.Error(),
					}
				} else {
					totalTools := 0
					for _, srvTools := range lf.Servers {
						totalTools += len(srvTools)
					}
					rep.LockfileCheck = &doctorCheckStatus{
						Path:    lockfilePath,
						Valid:   true,
						Summary: fmt.Sprintf("valid (%d server(s), %d pinned tool(s))", len(lf.Servers), totalTools),
					}
				}
			}

			rep.ReadinessGrade = readinessScoreToGrade(score)

			if asJSON {
				return writeIndentedJSON(stdout, rep)
			}

			fmt.Fprintf(stdout, "MCPGate Doctor v%s — Readiness Grade: %s\n\n", Version, rep.ReadinessGrade)
			fmt.Fprintf(stdout, "Host Sandbox Capabilities:\n")
			fmt.Fprintf(stdout, "  OS / Arch:         %s/%s\n", caps.OS, caps.Arch)
			fmt.Fprintf(stdout, "  Process Isolation: %s\n", caps.ProcessIsolation)
			fmt.Fprintf(stdout, "  Filesystem Jail:   %s\n", caps.FilesystemJail)
			fmt.Fprintf(stdout, "  Clean Env:         %v\n", caps.CleanEnvSupported)
			fmt.Fprintf(stdout, "  Memory Limit:      %v\n", caps.MemoryLimitSupported)
			for _, d := range caps.Details {
				fmt.Fprintf(stdout, "  Detail:            %s\n", d)
			}

			fmt.Fprintf(stdout, "\nDiscovered IDE MCP Configs (%d):\n", len(discovered))
			if len(discovered) == 0 {
				fmt.Fprintf(stdout, "  (none found on this host)\n")
			} else {
				for _, cfg := range discovered {
					fmt.Fprintf(stdout, "  - %-14s (%s): %s\n", cfg.Name, cfg.ID, cfg.Path)
				}
			}

			if rep.PolicyCheck != nil {
				status := "OK"
				if !rep.PolicyCheck.Valid {
					status = "ERROR"
				}
				fmt.Fprintf(stdout, "\nPolicy Check [%s]: %s — %s\n", status, rep.PolicyCheck.Path, rep.PolicyCheck.Summary)
			}
			if rep.LockfileCheck != nil {
				status := "OK"
				if !rep.LockfileCheck.Valid {
					status = "ERROR"
				}
				fmt.Fprintf(stdout, "Lockfile Check [%s]: %s — %s\n", status, rep.LockfileCheck.Path, rep.LockfileCheck.Summary)
			}

			if (rep.PolicyCheck != nil && !rep.PolicyCheck.Valid) || (rep.LockfileCheck != nil && !rep.LockfileCheck.Valid) {
				return &exitError{code: 1}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output diagnostics as JSON")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Validate an mcpgate.yaml policy file")
	cmd.Flags().StringVar(&lockfilePath, "lockfile", "", "Validate an mcpgate.lock schema lockfile")

	return cmd
}

func readinessScoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 45:
		return "D"
	default:
		return "F"
	}
}

// ============================================================================
// 7. mcpgate preset <ide>
// ============================================================================

func newPresetCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		presetName string
		policyPath string
		write      bool
		unwrap     bool
		selfMCP    bool
		customPath string
		binaryPath string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "preset <claude|claude-code|cursor|vscode|windsurf|zed> [flags]",
		Short: "Safely wrap or unwrap IDE MCP configs with MCPGate (or install MCPGate's self-MCP server)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ideCfg, err := preset.ResolveIDEConfig(args[0])
			if err != nil {
				return err
			}
			targetPath := ideCfg.Path
			if strings.TrimSpace(customPath) != "" {
				targetPath = customPath
			}

			if !unwrap && strings.TrimSpace(policyPath) == "" && !selfMCP {
				if _, err := policy.Preset(presetName); err != nil {
					return err
				}
			}

			shouldWrite := write && !dryRun

			if unwrap {
				opts := preset.UnwrapOptions{
					ServerKey:     ideCfg.ServerKey,
					RemoveSelfMCP: selfMCP,
					DryRun:        !shouldWrite,
				}
				raw, err := os.ReadFile(targetPath)
				if err != nil {
					return fmt.Errorf("read %s config %q: %w", ideCfg.Name, targetPath, err)
				}
				updated, res, err := preset.UnwrapConfig(raw, opts)
				if err != nil {
					return err
				}
				if shouldWrite && res.Changed {
					if err := preset.WriteFileAtomic(targetPath, updated, 0600); err != nil {
						return err
					}
					fmt.Fprintf(stdout, "Updated %s config %s: unwrapped=%v self_mcp_removed=%v\n",
						ideCfg.Name, targetPath, res.Unwrapped, res.SelfMCPRemoved)
					return nil
				}
				fmt.Fprintf(stdout, "[dry-run] %s config %s: unwrapped=%v not_wrapped=%v self_mcp_removed=%v (pass --write to apply)\n",
					ideCfg.Name, targetPath, res.Unwrapped, res.NotWrapped, res.SelfMCPRemoved)
				_, _ = stdout.Write(updated)
				return nil
			}

			opts := preset.WrapOptions{
				BinaryPath: binaryPath,
				Preset:     presetName,
				PolicyPath: policyPath,
				ServerKey:  ideCfg.ServerKey,
				SelfMCP:    selfMCP,
				DryRun:     !shouldWrite,
			}

			raw, err := os.ReadFile(targetPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) && selfMCP {
					raw = []byte("{}\n")
				} else {
					return fmt.Errorf("read %s config %q: %w", ideCfg.Name, targetPath, err)
				}
			}

			updated, res, err := preset.WrapConfig(raw, opts)
			if err != nil {
				return err
			}

			if shouldWrite {
				if res.Changed || !fileExistsLocal(targetPath) {
					if err := preset.WriteFileAtomic(targetPath, updated, 0600); err != nil {
						return err
					}
				}
				fmt.Fprintf(stdout, "Updated %s config %s: wrapped=%v already_wrapped=%v skipped=%v self_mcp_added=%v\n",
					ideCfg.Name, targetPath, res.Wrapped, res.AlreadyWrapped, res.Skipped, res.SelfMCPAdded)
				return nil
			}

			fmt.Fprintf(stdout, "[dry-run] %s config %s: wrapped=%v already_wrapped=%v skipped=%v self_mcp_added=%v (pass --write to apply)\n",
				ideCfg.Name, targetPath, res.Wrapped, res.AlreadyWrapped, res.Skipped, res.SelfMCPAdded)
			_, _ = stdout.Write(updated)
			return nil
		},
	}

	cmd.Flags().StringVar(&presetName, "preset", "balanced", "Policy preset to embed: balanced, strict, readonly, airgapped")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Custom mcpgate.yaml policy path to embed instead of --preset")
	cmd.Flags().BoolVar(&write, "write", false, "Atomically write changes to the IDE config file")
	cmd.Flags().BoolVar(&unwrap, "unwrap", false, "Revert MCPGate-wrapped servers back to their original commands")
	cmd.Flags().BoolVar(&selfMCP, "self-mcp", false, "Install (or with --unwrap, remove) MCPGate's own read-only MCP server entry")
	cmd.Flags().StringVar(&customPath, "path", "", "Override target IDE config file path")
	cmd.Flags().StringVar(&binaryPath, "binary", "mcpgate", "Path or executable name for mcpgate binary")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without modifying disk (overrides --write)")

	return cmd
}

// ============================================================================
// Shared Helpers
// ============================================================================

func loadPolicyWithPreset(policyPath, presetName string) (*policy.Policy, error) {
	if strings.TrimSpace(policyPath) != "" {
		return policy.LoadFile(policyPath)
	}
	return policy.Preset(presetName)
}

func envSliceToMap(vars []string) map[string]string {
	m := make(map[string]string, len(vars))
	for _, kv := range vars {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return "sess-" + hex.EncodeToString(b[:])
}

func writeIndentedJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func writeOutputFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create output directory %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write output file %q: %w", path, err)
	}
	return nil
}

func parseSeverityThreshold(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return 0, nil
	case "low":
		return 1, nil
	case "medium":
		return 2, nil
	case "high":
		return 3, nil
	case "critical":
		return 4, nil
	default:
		return 0, fmt.Errorf("invalid --fail-on %q (expected critical, high, medium, low, or none)", s)
	}
}

func severityLevelRank(sev policy.Severity) int {
	switch sev {
	case policy.SeverityCritical:
		return 4
	case policy.SeverityHigh:
		return 3
	case policy.SeverityMedium:
		return 2
	case policy.SeverityLow:
		return 1
	default:
		return 0
	}
}

func formatCountMap(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

func fileExistsLocal(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
