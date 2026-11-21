package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aloneangel45/mcpgate/pkg/audit"
	"github.com/aloneangel45/mcpgate/pkg/dlp"
	"github.com/aloneangel45/mcpgate/pkg/mcpproxy"
	"github.com/aloneangel45/mcpgate/pkg/policy"
	"github.com/aloneangel45/mcpgate/pkg/sandbox"
)

type rpcFrameMode int

const (
	rpcFrameUnknown rpcFrameMode = iota
	rpcFrameNDJSON
	rpcFrameContentLength
)

const maxSelfFrameBytes = 16 * 1024 * 1024 // 16 MiB

func newMCPCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run MCPGate as a read-only stdio MCP security advisor server",
		Long:  "Exposes 5 read-only MCP tools over stdio (NDJSON and Content-Length framing): audit_ide_configs, evaluate_policy, scan_secrets, inspect_audit_log, and sandbox_capabilities.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serveSelfMCP(stdin, stdout)
		},
	}
}

type selfRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func serveSelfMCP(in io.Reader, out io.Writer) error {
	br := bufio.NewReaderSize(in, 64*1024)
	for {
		raw, mode, err := readJSONRPCFrame(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var req selfRPCRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			resp := buildSelfError(json.RawMessage("null"), -32700, "Parse error: "+err.Error())
			if werr := writeJSONRPCFrame(out, resp, mode); werr != nil {
				return werr
			}
			continue
		}

		resp := handleSelfMCPRequest(req)
		if resp == nil {
			// Notification (no response expected).
			continue
		}
		if err := writeJSONRPCFrame(out, resp, mode); err != nil {
			return err
		}
	}
}

func handleSelfMCPRequest(req selfRPCRequest) []byte {
	hasID := len(bytes.TrimSpace(req.ID)) > 0

	switch req.Method {
	case "initialize":
		return buildSelfResult(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "mcpgate",
				"version": Version,
			},
		})

	case "notifications/initialized", "initialized":
		if !hasID {
			return nil
		}
		return buildSelfResult(req.ID, map[string]any{})

	case "ping":
		return buildSelfResult(req.ID, map[string]any{})

	case "tools/list":
		return buildSelfResult(req.ID, map[string]any{
			"tools": selfMCPTools(),
		})

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments,omitempty"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return buildSelfError(req.ID, -32602, "Invalid params: "+err.Error())
			}
		}
		resPayload, isErr, rpcErr := dispatchSelfMCPTool(strings.TrimSpace(params.Name), params.Arguments)
		if rpcErr != nil {
			return buildSelfError(req.ID, rpcErr.code, rpcErr.msg)
		}
		textBytes, err := json.MarshalIndent(resPayload, "", "  ")
		if err != nil {
			return buildSelfError(req.ID, -32603, "Marshal tool result failed: "+err.Error())
		}
		return buildSelfResult(req.ID, map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": string(textBytes),
				},
			},
			"isError": isErr,
		})

	default:
		if !hasID {
			return nil
		}
		return buildSelfError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

type selfRPCError struct {
	code int
	msg  string
}

func selfMCPTools() []mcpproxy.ToolDefinition {
	return []mcpproxy.ToolDefinition{
		{
			Name:        "audit_ide_configs",
			Description: "Audit local IDE MCP configuration files or a specific config path/directory for OWASP MCP Top 10 risks (read-only).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Optional path to a specific MCP config file, mcpgate.yaml policy, or directory. If omitted, audits all discovered IDE configs.",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "evaluate_policy",
			Description: "Dry-run a zero-trust MCPGate policy or preset against a tool name, path argument, outbound URL/SSRF target, or text payload (read-only).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"preset": map[string]any{
						"type":        "string",
						"description": "Built-in preset name: strict, balanced, readonly, or airgapped (default: balanced).",
					},
					"policy_path": map[string]any{
						"type":        "string",
						"description": "Optional path to a custom mcpgate.yaml policy file.",
					},
					"work_dir": map[string]any{
						"type":        "string",
						"description": "Optional working directory for relative path and .env resolution.",
					},
					"tool": map[string]any{
						"type":        "string",
						"description": "Optional MCP tool name to evaluate.",
					},
					"path_arg": map[string]any{
						"type":        "string",
						"description": "Optional filesystem path argument to evaluate.",
					},
					"url": map[string]any{
						"type":        "string",
						"description": "Optional outbound URL or host to check against domain and SSRF policies.",
					},
					"payload": map[string]any{
						"type":        "string",
						"description": "Optional text payload to scan with the DLP engine.",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "scan_secrets",
			Description: "Scan text for hardcoded secrets, tokens, private keys, and fingerprinted .env credentials. Always returns masked MatchPreview values only and never echoes raw secrets.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"text"},
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "Text to inspect for secrets and PII.",
					},
					"load_dotenv": map[string]any{
						"type":        "boolean",
						"description": "Whether to fingerprint local .env files in work_dir (default: false).",
					},
					"work_dir": map[string]any{
						"type":        "string",
						"description": "Optional working directory used when load_dotenv is true.",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "inspect_audit_log",
			Description: "Parse, filter, and summarize an MCPGate JSONL runtime security audit log file (read-only).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Filesystem path to the audit JSONL log file.",
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Optional severity filter (critical, high, medium, low, info).",
					},
					"category": map[string]any{
						"type":        "string",
						"description": "Optional category filter (dlp, egress, ssrf, poisoning, rugpull, path, tool_policy, breaker, sandbox).",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "sandbox_capabilities",
			Description: "Inspect available OS-level process isolation, clean-env, memory limit, and filesystem jail capabilities on this host (read-only).",
			InputSchema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
	}
}

func dispatchSelfMCPTool(name string, args map[string]any) (any, bool, *selfRPCError) {
	switch name {
	case "audit_ide_configs":
		p := strArg(args, "path")
		var (
			rep *audit.AuditReport
			err error
		)
		if p != "" {
			targets, tErr := collectAuditTargets([]string{p}, false)
			if tErr != nil {
				return map[string]any{"error": tErr.Error()}, true, nil
			}
			rep, err = audit.AuditFiles(targets)
		} else {
			rep, err = audit.AuditAllIDEs()
		}
		if err != nil {
			return map[string]any{"error": err.Error()}, true, nil
		}
		return rep, false, nil

	case "evaluate_policy":
		var paths []string
		if p := strArg(args, "path_arg"); p != "" {
			paths = append(paths, p)
		}
		presetName := strArg(args, "preset")
		if presetName == "" && strArg(args, "policy_path") == "" {
			presetName = "balanced"
		}
		rep, err := evaluatePolicyInput(policyEvalInput{
			PolicyPath: strArg(args, "policy_path"),
			Preset:     presetName,
			WorkDir:    strArg(args, "work_dir"),
			Tool:       strArg(args, "tool"),
			Paths:      paths,
			URL:        strArg(args, "url"),
			Payload:    strArg(args, "payload"),
		})
		if err != nil {
			return map[string]any{"error": err.Error()}, true, nil
		}
		return rep, false, nil

	case "scan_secrets":
		text, ok := args["text"].(string)
		if !ok {
			return map[string]any{"error": "required string argument 'text' is missing"}, true, nil
		}
		loadDotEnv := boolArg(args, "load_dotenv")
		workDir := strArg(args, "work_dir")
		scanner, err := dlp.NewScanner(policy.DLPPolicy{
			Enabled:    true,
			Action:     policy.ActionBlock,
			LoadDotEnv: loadDotEnv,
		}, workDir)
		if err != nil {
			return map[string]any{"error": err.Error()}, true, nil
		}
		findings := scanner.Scan(text)
		type maskedFinding struct {
			RuleID       string          `json:"rule_id"`
			Name         string          `json:"name"`
			Severity     policy.Severity `json:"severity"`
			MatchPreview string          `json:"match_preview"`
			SHA256Prefix string          `json:"sha256_prefix"`
			Offset       int             `json:"offset"`
			Length       int             `json:"length"`
		}
		masked := make([]maskedFinding, len(findings))
		for i, f := range findings {
			masked[i] = maskedFinding{
				RuleID:       f.RuleID,
				Name:         f.Name,
				Severity:     f.Severity,
				MatchPreview: f.MatchPreview,
				SHA256Prefix: f.SHA256Prefix,
				Offset:       f.Offset,
				Length:       f.Length,
			}
		}
		return map[string]any{
			"clean":          len(masked) == 0,
			"findings_count": len(masked),
			"dotenv_loaded":  scanner.DotEnvCount(),
			"findings":       masked,
		}, false, nil

	case "inspect_audit_log":
		logPath := strArg(args, "path")
		if logPath == "" {
			return map[string]any{"error": "required string argument 'path' is missing"}, true, nil
		}
		events, err := audit.LoadEvents(logPath)
		if err != nil {
			return map[string]any{"error": err.Error()}, true, nil
		}
		filtered := filterSecurityEvents(events, strArg(args, "category"), strArg(args, "severity"))
		summary := audit.Summarize(filtered)
		return map[string]any{
			"summary": summary,
			"events":  filtered,
		}, false, nil

	case "sandbox_capabilities":
		return sandbox.Capabilities(), false, nil

	default:
		return nil, true, &selfRPCError{code: -32602, msg: fmt.Sprintf("Unknown tool: %s", name)}
	}
}

func strArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func boolArg(args map[string]any, key string) bool {
	if args == nil {
		return false
	}
	v, _ := args[key].(bool)
	return v
}

func buildSelfResult(id json.RawMessage, result any) []byte {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 {
		return nil
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(trimmed),
		"result":  result,
	})
	return b
}

func buildSelfError(id json.RawMessage, code int, msg string) []byte {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 {
		trimmed = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(trimmed),
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
	return b
}

// readJSONRPCFrame reads a single NDJSON or LSP Content-Length framed JSON-RPC message.
func readJSONRPCFrame(br *bufio.Reader) ([]byte, rpcFrameMode, error) {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return nil, rpcFrameUnknown, err
		}
		if b[0] == '\r' || b[0] == '\n' || b[0] == ' ' || b[0] == '\t' {
			_, _ = br.ReadByte()
			continue
		}

		if b[0] == '{' || b[0] == '[' {
			line, err := br.ReadBytes('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, rpcFrameUnknown, err
			}
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 {
				if errors.Is(err, io.EOF) {
					return nil, rpcFrameUnknown, io.EOF
				}
				continue
			}
			return trimmed, rpcFrameNDJSON, nil
		}

		contentLength := -1
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, rpcFrameUnknown, err
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break
			}
			if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
				k := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
				v := strings.TrimSpace(trimmed[idx+1:])
				if k == "content-length" {
					n, convErr := strconv.Atoi(v)
					if convErr != nil || n < 0 || n > maxSelfFrameBytes {
						return nil, rpcFrameUnknown, fmt.Errorf("invalid Content-Length header %q", v)
					}
					contentLength = n
				}
			}
		}
		if contentLength < 0 {
			return nil, rpcFrameUnknown, fmt.Errorf("missing Content-Length header")
		}
		buf := make([]byte, contentLength)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, rpcFrameUnknown, err
		}
		return buf, rpcFrameContentLength, nil
	}
}

func writeJSONRPCFrame(w io.Writer, payload []byte, mode rpcFrameMode) error {
	if mode == rpcFrameContentLength {
		header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
		if _, err := io.WriteString(w, header); err != nil {
			return err
		}
		_, err := w.Write(payload)
		return err
	}
	out := payload
	if bytes.ContainsAny(payload, "\r\n") {
		var compact bytes.Buffer
		if json.Compact(&compact, payload) == nil {
			out = compact.Bytes()
		}
	}
	if _, err := w.Write(out); err != nil {
		return err
	}
	_, err := w.Write([]byte{'\n'})
	return err
}
