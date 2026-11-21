package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// JSON-RPC 2.0 application error codes used by MCPGate when blocking requests or outputs.
const (
	ErrCodePolicyDenied  = -32001
	ErrCodeQuarantined   = -32002
	ErrCodePathBlocked   = -32003
	ErrCodeCircuitBroken = -32004
	ErrCodeDLPBlocked    = -32005
)

const maxFrameBytes = 64 * 1024 * 1024 // 64 MiB defensive limit

// DLPFinding represents a sensitive secret or PII match returned by a PayloadScanner.
type DLPFinding struct {
	RuleID       string          `json:"rule_id"`
	Name         string          `json:"name"`
	Severity     policy.Severity `json:"severity"`
	MatchPreview string          `json:"match_preview"`
}

// PayloadScanner decouples mcpproxy from concrete DLP scanner implementations (such as pkg/dlp).
type PayloadScanner interface {
	ScanPayload(text string) []DLPFinding
	RedactPayload(text string) (string, []DLPFinding)
}

// ApproverFunc prompts an operator when a tool matches policy.ActionPrompt.
// Returning true allows the single invocation; returning false blocks it.
type ApproverFunc func(tool string, args map[string]any, reason string) bool

// Options configures a live bidirectional MCPGate Proxy instance.
type Options struct {
	Policy     *policy.Policy
	ServerName string
	WorkDir    string
	SessionID  string
	Scanner    PayloadScanner
	Lockfile   *Lockfile
	Approver   ApproverFunc
	OnEvent    func(policy.SecurityEvent)
}

// Stats reports live thread-safe operational counters for a Proxy session.
type Stats struct {
	TotalRequests int64 `json:"total_requests"`
	Allowed       int64 `json:"allowed"`
	Blocked       int64 `json:"blocked"`
	Quarantined   int64 `json:"quarantined"`
	Redacted      int64 `json:"redacted"`
	BreakerTrips  int64 `json:"breaker_trips"`
}

// QuarantineEntry records why a tool was stripped and blocked from invocation.
type QuarantineEntry struct {
	ToolName string          `json:"tool_name"`
	Category string          `json:"category"`
	RuleID   string          `json:"rule_id"`
	Severity policy.Severity `json:"severity"`
	Reason   string          `json:"reason"`
	At       time.Time       `json:"at"`
}

type frameMode int

const (
	frameUnknown frameMode = iota
	frameNDJSON
	frameContentLength
)

type pendingRequest struct {
	method   string
	toolName string
}

// Proxy is a bidirectional live MCP JSON-RPC 2.0 security proxy supporting both
// NDJSON and Content-Length stdio framing automatically.
type Proxy struct {
	pol        *policy.Policy
	serverName string
	workDir    string
	sessionID  string
	scanner    PayloadScanner
	lockfile   *Lockfile
	breaker    *CircuitBreaker
	approver   ApproverFunc
	onEvent    func(policy.SecurityEvent)

	mu          sync.RWMutex
	pending     map[string]pendingRequest
	quarantined map[string]QuarantineEntry
	clientMode  frameMode

	totalRequests atomic.Int64
	allowed       atomic.Int64
	blocked       atomic.Int64
	quarantinedN  atomic.Int64
	redacted      atomic.Int64
	breakerTrips  atomic.Int64
}

// NewProxy initializes a new live MCP security proxy.
func NewProxy(opts Options) (*Proxy, error) {
	pol := opts.Policy
	if pol == nil {
		var err error
		pol, err = policy.Preset("balanced")
		if err != nil {
			return nil, err
		}
	}
	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	lf := opts.Lockfile
	if lf == nil {
		var err error
		lf, err = LoadOrCreateLockfile(pol.MCP.LockfilePath)
		if err != nil {
			return nil, fmt.Errorf("initialize lockfile: %w", err)
		}
	}

	serverName := strings.TrimSpace(opts.ServerName)
	if serverName == "" {
		serverName = "default"
	}

	return &Proxy{
		pol:        pol,
		serverName: serverName,
		workDir:    opts.WorkDir,
		sessionID:  opts.SessionID,
		scanner:    opts.Scanner,
		lockfile:   lf,
		breaker: NewCircuitBreaker(BreakerConfig{
			MaxCallsPerMinute:    pol.MCP.MaxCallsPerMinute,
			MaxConsecutiveErrors: pol.MCP.MaxConsecutiveErrors,
			MaxIdenticalCalls:    pol.MCP.MaxIdenticalCalls,
		}),
		approver:    opts.Approver,
		onEvent:     opts.OnEvent,
		pending:     make(map[string]pendingRequest),
		quarantined: make(map[string]QuarantineEntry),
	}, nil
}

// Stats returns a snapshot of the live security counters.
func (p *Proxy) Stats() Stats {
	return Stats{
		TotalRequests: p.totalRequests.Load(),
		Allowed:       p.allowed.Load(),
		Blocked:       p.blocked.Load(),
		Quarantined:   p.quarantinedN.Load(),
		Redacted:      p.redacted.Load(),
		BreakerTrips:  p.breakerTrips.Load(),
	}
}

// Breaker exposes the proxy's circuit breaker for inspection or testing.
func (p *Proxy) Breaker() *CircuitBreaker {
	return p.breaker
}

// Lockfile exposes the proxy's tool lockfile.
func (p *Proxy) Lockfile() *Lockfile {
	return p.lockfile
}

// QuarantinedTools returns a snapshot of tools currently quarantined by MCPGate.
func (p *Proxy) QuarantinedTools() map[string]QuarantineEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]QuarantineEntry, len(p.quarantined))
	for k, v := range p.quarantined {
		out[k] = v
	}
	return out
}

// Run pumps JSON-RPC messages bidirectionally between the MCP client (clientIn/clientOut)
// and the downstream MCP server (serverIn/serverOut) until EOF or context cancellation.
func (p *Proxy) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var clientOutMu sync.Mutex
	var serverInMu sync.Mutex

	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)

	// Client -> Server loop.
	go func() {
		defer func() {
			// Signal EOF to the downstream MCP server so it shuts down cleanly.
			if c, ok := serverIn.(io.Closer); ok {
				_ = c.Close()
			}
		}()

		br := bufio.NewReaderSize(clientIn, 64*1024)
		for {
			if ctx.Err() != nil {
				clientDone <- ctx.Err()
				return
			}
			raw, mode, err := readFrame(br)
			if err != nil {
				if errors.Is(err, io.EOF) {
					clientDone <- nil
					return
				}
				clientDone <- err
				return
			}

			p.setClientMode(mode)

			forwardBytes, syntheticResp := p.processClientMessage(raw)
			if syntheticResp != nil {
				if werr := writeFrame(clientOut, &clientOutMu, syntheticResp, mode); werr != nil {
					clientDone <- werr
					return
				}
				continue
			}
			if forwardBytes != nil {
				if werr := writeFrame(serverIn, &serverInMu, forwardBytes, mode); werr != nil {
					clientDone <- werr
					return
				}
			}
		}
	}()

	// Server -> Client loop.
	go func() {
		br := bufio.NewReaderSize(serverOut, 64*1024)
		for {
			if ctx.Err() != nil {
				serverDone <- ctx.Err()
				return
			}
			raw, mode, err := readFrame(br)
			if err != nil {
				if errors.Is(err, io.EOF) {
					serverDone <- nil
					return
				}
				serverDone <- err
				return
			}

			outBytes := p.processServerMessage(raw)
			outMode := p.getClientMode()
			if outMode == frameUnknown {
				outMode = mode
			}
			if outBytes != nil {
				if werr := writeFrame(clientOut, &clientOutMu, outBytes, outMode); werr != nil {
					serverDone <- werr
					return
				}
			}
		}
	}()

	var cErr, sErr error
	cFinished, sFinished := false, false
	for !cFinished || !sFinished {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cErr = <-clientDone:
			cFinished = true
		case sErr = <-serverDone:
			sFinished = true
			// If the downstream server exited cleanly or crashed, stop waiting for stdin.
			if !cFinished {
				return sErr
			}
		}
	}

	if sErr != nil {
		return sErr
	}
	return cErr
}

func (p *Proxy) setClientMode(m frameMode) {
	if m == frameUnknown {
		return
	}
	p.mu.Lock()
	if p.clientMode == frameUnknown {
		p.clientMode = m
	}
	p.mu.Unlock()
}

func (p *Proxy) getClientMode() frameMode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.clientMode
}

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

func (p *Proxy) processClientMessage(raw []byte) (forward []byte, syntheticResponse []byte) {
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Pass malformed or non-object payloads through untouched.
		return raw, nil
	}

	idKey := canonicalIDKey(env.ID)

	if env.Method == "tools/list" {
		if idKey != "" {
			p.recordPending(idKey, pendingRequest{method: "tools/list"})
		}
		return raw, nil
	}

	if env.Method != "tools/call" {
		return raw, nil
	}

	p.totalRequests.Add(1)

	var params toolCallParams
	if len(env.Params) > 0 {
		_ = json.Unmarshal(env.Params, &params)
	}
	toolName := strings.TrimSpace(params.Name)

	// 1. Circuit breaker check.
	if trip := p.breaker.AllowCall(toolName, params.Arguments); trip.Tripped {
		p.blocked.Add(1)
		p.breakerTrips.Add(1)
		p.emit(policy.SecurityEvent{
			Category: "breaker",
			Severity: policy.SeverityHigh,
			Action:   "blocked",
			RuleID:   BreakerRuleID,
			Tool:     toolName,
			Message:  trip.Reason,
			Metadata: map[string]string{"kind": trip.Kind},
		})
		return nil, buildErrorResponse(env.ID, ErrCodeCircuitBroken, "MCPGate circuit breaker tripped: "+trip.Reason, map[string]any{
			"rule_id": BreakerRuleID,
			"kind":    trip.Kind,
		})
	}

	// 2. Quarantine check (poisoned or rug-pulled tools).
	if q, ok := p.getQuarantined(toolName); ok {
		p.blocked.Add(1)
		p.emit(policy.SecurityEvent{
			Category: q.Category,
			Severity: policy.SeverityCritical,
			Action:   "blocked",
			RuleID:   q.RuleID,
			Tool:     toolName,
			Message:  "blocked invocation of quarantined tool: " + q.Reason,
		})
		return nil, buildErrorResponse(env.ID, ErrCodeQuarantined, "MCPGate blocked quarantined tool "+toolName+": "+q.Reason, map[string]any{
			"rule_id": q.RuleID,
			"tool":    toolName,
		})
	}

	// 3. Tool authorization policy (deny / prompt / allow).
	toolDec := p.pol.EvaluateTool(toolName)
	switch toolDec.Action {
	case policy.ActionDeny:
		p.blocked.Add(1)
		p.emit(policy.SecurityEvent{
			Category: "tool_policy",
			Severity: toolDec.Severity,
			Action:   "blocked",
			RuleID:   toolDec.RuleID,
			Tool:     toolName,
			Message:  toolDec.Reason,
		})
		return nil, buildErrorResponse(env.ID, ErrCodePolicyDenied, "MCPGate policy denied tool: "+toolDec.Reason, map[string]any{
			"rule_id": toolDec.RuleID,
			"tool":    toolName,
		})

	case policy.ActionPrompt:
		approved := false
		if p.approver != nil {
			approved = p.approver(toolName, params.Arguments, toolDec.Reason)
		}
		if !approved {
			p.blocked.Add(1)
			p.emit(policy.SecurityEvent{
				Category: "tool_policy",
				Severity: toolDec.Severity,
				Action:   "blocked",
				RuleID:   toolDec.RuleID,
				Tool:     toolName,
				Message:  "tool invocation denied at approval gate: " + toolDec.Reason,
			})
			return nil, buildErrorResponse(env.ID, ErrCodePolicyDenied, "MCPGate tool approval denied: "+toolDec.Reason, map[string]any{
				"rule_id": toolDec.RuleID,
				"tool":    toolName,
			})
		}
		p.emit(policy.SecurityEvent{
			Category: "tool_policy",
			Severity: policy.SeverityInfo,
			Action:   "prompted",
			RuleID:   toolDec.RuleID,
			Tool:     toolName,
			Message:  "tool invocation approved by operator",
		})
	}

	// 4. Recursive path extraction & filesystem policy check.
	paths := ExtractPaths(params.Arguments)
	for _, candidate := range paths {
		pathDec := p.pol.EvaluatePath(candidate, p.workDir)
		if pathDec.Action == policy.ActionDeny {
			p.blocked.Add(1)
			p.emit(policy.SecurityEvent{
				Category: "path",
				Severity: pathDec.Severity,
				Action:   "blocked",
				RuleID:   pathDec.RuleID,
				Tool:     toolName,
				Target:   candidate,
				Message:  pathDec.Reason,
			})
			return nil, buildErrorResponse(env.ID, ErrCodePathBlocked, "MCPGate filesystem policy blocked path: "+pathDec.Reason, map[string]any{
				"rule_id": pathDec.RuleID,
				"tool":    toolName,
				"target":  candidate,
			})
		}
	}

	// 5. DLP scanning on tool arguments.
	outRaw := raw
	if p.pol.DLP.Enabled && p.scanner != nil && len(params.Arguments) > 0 {
		action := p.pol.DLP.Action
		if action == "" {
			action = policy.ActionBlock
		}
		var findings []DLPFinding
		var modified bool
		if action == policy.ActionRedact {
			var newArgs any
			newArgs, findings, modified = redactAny(params.Arguments, p.scanner)
			if len(findings) > 0 && modified {
				if updated, ok := replaceRequestArguments(raw, newArgs); ok {
					outRaw = updated
				}
			}
		} else {
			scanAny(params.Arguments, p.scanner, &findings)
		}

		if len(findings) > 0 {
			sev := maxDLPFindingSeverity(findings)
			ruleID := findings[0].RuleID
			msg := fmt.Sprintf("DLP matched %d secret(s) in tool %q arguments (%s)", len(findings), toolName, findings[0].Name)
			switch action {
			case policy.ActionBlock:
				p.blocked.Add(1)
				p.emit(policy.SecurityEvent{
					Category: "dlp",
					Severity: sev,
					Action:   "blocked",
					RuleID:   ruleID,
					Tool:     toolName,
					Message:  msg,
				})
				return nil, buildErrorResponse(env.ID, ErrCodeDLPBlocked, "MCPGate DLP blocked sensitive data in tool arguments: "+findings[0].Name, map[string]any{
					"rule_id": ruleID,
					"tool":    toolName,
				})
			case policy.ActionRedact:
				p.redacted.Add(1)
				p.emit(policy.SecurityEvent{
					Category: "dlp",
					Severity: sev,
					Action:   "redacted",
					RuleID:   ruleID,
					Tool:     toolName,
					Message:  msg,
				})
			case policy.ActionWarn:
				p.emit(policy.SecurityEvent{
					Category: "dlp",
					Severity: sev,
					Action:   "warned",
					RuleID:   ruleID,
					Tool:     toolName,
					Message:  msg,
				})
			}
		}
	}

	p.allowed.Add(1)
	if idKey != "" {
		p.recordPending(idKey, pendingRequest{method: "tools/call", toolName: toolName})
	}
	if p.pol.Audit.LogAllowed {
		p.emit(policy.SecurityEvent{
			Category: "tool_policy",
			Severity: policy.SeverityInfo,
			Action:   "allowed",
			RuleID:   toolDec.RuleID,
			Tool:     toolName,
			Message:  fmt.Sprintf("tool %q invocation allowed", toolName),
		})
	}
	return outRaw, nil
}

func (p *Proxy) processServerMessage(raw []byte) []byte {
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return raw
	}

	idKey := canonicalIDKey(env.ID)
	if idKey == "" {
		// Notification or malformed message without ID; pass through.
		return raw
	}

	req, ok := p.popPending(idKey)
	if !ok {
		return raw
	}

	switch req.method {
	case "tools/list":
		return p.inspectToolsListResponse(raw, env)
	case "tools/call":
		return p.inspectToolCallResponse(raw, env, req.toolName)
	default:
		return raw
	}
}

func (p *Proxy) inspectToolsListResponse(raw []byte, env rpcEnvelope) []byte {
	if len(env.Result) == 0 {
		return raw
	}

	var resultObj map[string]json.RawMessage
	if err := json.Unmarshal(env.Result, &resultObj); err != nil {
		return raw
	}
	rawToolsArr, ok := resultObj["tools"]
	if !ok || len(rawToolsArr) == 0 {
		return raw
	}

	var rawTools []json.RawMessage
	if err := json.Unmarshal(rawToolsArr, &rawTools); err != nil {
		return raw
	}

	parsedTools := make([]ToolDefinition, len(rawTools))
	for i, rt := range rawTools {
		_ = json.Unmarshal(rt, &parsedTools[i])
	}

	// Build violation maps per tool name.
	stripSet := make(map[string]bool)
	quarantinedThisPass := make(map[string]bool)

	// 1. Tool-poisoning scan.
	if p.pol.MCP.BlockPoisoning || p.pol.MCP.QuarantinePoisoned {
		for _, tool := range parsedTools {
			findings := ScanToolPoisoning(tool)
			if len(findings) == 0 {
				continue
			}
			sev := maxPoisonSeverity(findings)
			reason := fmt.Sprintf("%s in %s (%s)", findings[0].Description, findings[0].Field, findings[0].Evidence)

			if p.pol.MCP.QuarantinePoisoned || p.pol.MCP.BlockPoisoning {
				stripSet[tool.Name] = true
				if !quarantinedThisPass[tool.Name] {
					quarantinedThisPass[tool.Name] = true
					p.quarantineTool(QuarantineEntry{
						ToolName: tool.Name,
						Category: "poisoning",
						RuleID:   "MCP01-TOOL-POISONING",
						Severity: sev,
						Reason:   reason,
						At:       time.Now().UTC(),
					})
				}
				p.emit(policy.SecurityEvent{
					Category: "poisoning",
					Severity: sev,
					Action:   "quarantined",
					RuleID:   "MCP01-TOOL-POISONING",
					Tool:     tool.Name,
					Message:  fmt.Sprintf("quarantined poisoned tool %q: %s", tool.Name, reason),
					Metadata: map[string]string{
						"findings": strconv.Itoa(len(findings)),
						"field":    findings[0].Field,
					},
				})
			}
		}
	}

	// 2. SHA-256 lockfile & mid-session rug-pull verification.
	lockMode := strings.ToLower(strings.TrimSpace(p.pol.MCP.LockMode))
	if p.lockfile != nil && lockMode != "" && lockMode != "off" {
		violations := p.lockfile.VerifyTools(p.serverName, parsedTools, lockMode)
		for _, v := range violations {
			if lockMode == "enforce" {
				stripSet[v.ToolName] = true
				if !quarantinedThisPass[v.ToolName] {
					quarantinedThisPass[v.ToolName] = true
					p.quarantineTool(QuarantineEntry{
						ToolName: v.ToolName,
						Category: "rugpull",
						RuleID:   v.RuleID,
						Severity: v.Severity,
						Reason:   v.Message,
						At:       time.Now().UTC(),
					})
				}
				p.emit(policy.SecurityEvent{
					Category: "rugpull",
					Severity: v.Severity,
					Action:   "quarantined",
					RuleID:   v.RuleID,
					Tool:     v.ToolName,
					Message:  v.Message,
					Metadata: map[string]string{
						"kind":          v.Kind,
						"expected_hash": v.ExpectedHash,
						"actual_hash":   v.ActualHash,
					},
				})
			} else {
				p.emit(policy.SecurityEvent{
					Category: "rugpull",
					Severity: v.Severity,
					Action:   "warned",
					RuleID:   v.RuleID,
					Tool:     v.ToolName,
					Message:  v.Message,
					Metadata: map[string]string{
						"kind":          v.Kind,
						"expected_hash": v.ExpectedHash,
						"actual_hash":   v.ActualHash,
					},
				})
			}
		}
	}

	if len(stripSet) == 0 {
		return raw
	}

	filtered := make([]json.RawMessage, 0, len(rawTools))
	for i, rt := range rawTools {
		if !stripSet[parsedTools[i].Name] {
			filtered = append(filtered, rt)
		}
	}

	newToolsBytes, err := json.Marshal(filtered)
	if err != nil {
		return raw
	}
	resultObj["tools"] = newToolsBytes
	newResultBytes, err := json.Marshal(resultObj)
	if err != nil {
		return raw
	}

	var fullMsg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fullMsg); err != nil {
		return raw
	}
	fullMsg["result"] = newResultBytes
	out, err := json.Marshal(fullMsg)
	if err != nil {
		return raw
	}
	return out
}

func (p *Proxy) inspectToolCallResponse(raw []byte, env rpcEnvelope, toolName string) []byte {
	// 1. Track consecutive errors for the circuit breaker.
	isErr := len(env.Error) > 0 && string(bytes.TrimSpace(env.Error)) != "null"
	if !isErr && len(env.Result) > 0 {
		var resFlag struct {
			IsError bool `json:"isError"`
		}
		if json.Unmarshal(env.Result, &resFlag) == nil && resFlag.IsError {
			isErr = true
		}
	}
	if trip := p.breaker.RecordResult(isErr); trip.Tripped {
		p.breakerTrips.Add(1)
		p.emit(policy.SecurityEvent{
			Category: "breaker",
			Severity: policy.SeverityHigh,
			Action:   "blocked",
			RuleID:   BreakerRuleID,
			Tool:     toolName,
			Message:  trip.Reason,
			Metadata: map[string]string{"kind": trip.Kind},
		})
	}

	// 2. Scan tool output for leaked secrets (DLP).
	if !p.pol.DLP.Enabled || p.scanner == nil || len(env.Result) == 0 {
		return raw
	}

	var resultAny any
	if err := json.Unmarshal(env.Result, &resultAny); err != nil {
		return raw
	}

	action := p.pol.DLP.Action
	if action == "" {
		action = policy.ActionBlock
	}

	var findings []DLPFinding
	var redactedVal any
	var modified bool
	if action == policy.ActionRedact {
		redactedVal, findings, modified = redactAny(resultAny, p.scanner)
	} else {
		scanAny(resultAny, p.scanner, &findings)
	}

	if len(findings) == 0 {
		return raw
	}

	sev := maxDLPFindingSeverity(findings)
	ruleID := findings[0].RuleID
	msg := fmt.Sprintf("DLP matched %d secret(s) in tool %q output (%s)", len(findings), toolName, findings[0].Name)

	switch action {
	case policy.ActionBlock:
		p.blocked.Add(1)
		p.emit(policy.SecurityEvent{
			Category: "dlp",
			Severity: sev,
			Action:   "blocked",
			RuleID:   ruleID,
			Tool:     toolName,
			Message:  msg,
		})
		return buildErrorResponse(env.ID, ErrCodeDLPBlocked, "MCPGate DLP blocked sensitive secret in tool output: "+findings[0].Name, map[string]any{
			"rule_id": ruleID,
			"tool":    toolName,
		})

	case policy.ActionRedact:
		p.redacted.Add(1)
		p.emit(policy.SecurityEvent{
			Category: "dlp",
			Severity: sev,
			Action:   "redacted",
			RuleID:   ruleID,
			Tool:     toolName,
			Message:  msg,
		})
		if modified {
			var fullMsg map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fullMsg); err == nil {
				if newRes, err := json.Marshal(redactedVal); err == nil {
					fullMsg["result"] = newRes
					if out, err := json.Marshal(fullMsg); err == nil {
						return out
					}
				}
			}
		}
		return raw

	case policy.ActionWarn:
		p.emit(policy.SecurityEvent{
			Category: "dlp",
			Severity: sev,
			Action:   "warned",
			RuleID:   ruleID,
			Tool:     toolName,
			Message:  msg,
		})
		return raw
	}

	return raw
}

func (p *Proxy) quarantineTool(entry QuarantineEntry) {
	p.mu.Lock()
	_, existed := p.quarantined[entry.ToolName]
	p.quarantined[entry.ToolName] = entry
	p.mu.Unlock()
	if !existed {
		p.quarantinedN.Add(1)
	}
}

func (p *Proxy) getQuarantined(toolName string) (QuarantineEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	q, ok := p.quarantined[toolName]
	return q, ok
}

func (p *Proxy) recordPending(idKey string, req pendingRequest) {
	p.mu.Lock()
	p.pending[idKey] = req
	p.mu.Unlock()
}

func (p *Proxy) popPending(idKey string) (pendingRequest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	req, ok := p.pending[idKey]
	if ok {
		delete(p.pending, idKey)
	}
	return req, ok
}

func (p *Proxy) emit(ev policy.SecurityEvent) {
	if p.onEvent == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.SessionID == "" {
		ev.SessionID = p.sessionID
	}
	if ev.Server == "" {
		ev.Server = p.serverName
	}
	p.onEvent(ev)
}

func canonicalIDKey(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	return string(trimmed)
}

func buildErrorResponse(id json.RawMessage, code int, message string, data map[string]any) []byte {
	trimmedID := bytes.TrimSpace(id)
	if len(trimmedID) == 0 {
		// JSON-RPC notifications (without an ID) must not receive a response.
		return nil
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(trimmedID),
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data":    data,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func replaceRequestArguments(raw []byte, newArgs any) ([]byte, bool) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, false
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(msg["params"], &params); err != nil {
		return nil, false
	}
	argBytes, err := json.Marshal(newArgs)
	if err != nil {
		return nil, false
	}
	params["arguments"] = argBytes
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return nil, false
	}
	msg["params"] = paramBytes
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, false
	}
	return out, true
}

// ExtractPaths recursively extracts path-like string arguments from MCP tool call parameters
// for validation with policy.EvaluatePath.
func ExtractPaths(args map[string]any) []string {
	if len(args) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	extractPathsRecursive("", args, seen, &out)
	return out
}

var pathArgKeys = map[string]bool{
	"path":        true,
	"paths":       true,
	"file":        true,
	"files":       true,
	"filepath":    true,
	"file_path":   true,
	"filename":    true,
	"file_name":   true,
	"dir":         true,
	"directory":   true,
	"folder":      true,
	"uri":         true,
	"target":      true,
	"cwd":         true,
	"workdir":     true,
	"work_dir":    true,
	"source":      true,
	"src":         true,
	"dest":        true,
	"destination": true,
	"root":        true,
	"location":    true,
}

func isPathKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if pathArgKeys[k] {
		return true
	}
	return strings.HasSuffix(k, "_path") ||
		strings.HasSuffix(k, "_file") ||
		strings.HasSuffix(k, "_dir") ||
		strings.HasSuffix(k, "_uri")
}

func extractPathsRecursive(parentKey string, v any, seen map[string]struct{}, out *[]string) {
	switch val := v.(type) {
	case string:
		if p, ok := normalizeCandidatePath(parentKey, val); ok {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				*out = append(*out, p)
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			extractPathsRecursive(k, val[k], seen, out)
		}
	case []any:
		for _, item := range val {
			extractPathsRecursive(parentKey, item, seen, out)
		}
	}
}

func normalizeCandidatePath(parentKey, raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}

	lower := strings.ToLower(s)

	// Handle file:// URIs explicitly; ignore non-file URLs (http://, https://, etc.).
	if strings.HasPrefix(lower, "file://") {
		p := strings.TrimPrefix(s[7:], "localhost")
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			// Windows file:///C:/... -> C:/...
			p = p[1:]
		}
		return p, p != ""
	}
	if strings.Contains(lower, "://") {
		return "", false
	}

	if isPathKey(parentKey) {
		return s, true
	}

	if looksLikeFilesystemPath(s) {
		return s, true
	}
	return "", false
}

func looksLikeFilesystemPath(s string) bool {
	if strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "~/") ||
		strings.HasPrefix(s, `~\`) ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, `.\`) ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, `..\`) ||
		strings.HasPrefix(s, `\\`) {
		return true
	}
	// Windows drive letter path (e.g. C:\ or D:/).
	if len(s) >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	// Traversal sequence embedded inside a relative path.
	if strings.Contains(s, "../") || strings.Contains(s, `..\`) {
		return true
	}
	// Direct sensitive filename references even without path separators (e.g. ".env", "id_rsa").
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(s, `\`, "/")))
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return true
	case base == "id_rsa" || base == "id_ed25519" || base == "id_ecdsa" || base == "credentials.json" ||
		base == ".npmrc" || base == ".pypirc" || base == ".netrc" || base == ".git-credentials":
		return true
	}
	return false
}

func scanAny(v any, scanner PayloadScanner, findings *[]DLPFinding) {
	switch val := v.(type) {
	case string:
		if val != "" {
			*findings = append(*findings, scanner.ScanPayload(val)...)
		}
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			scanAny(val[k], scanner, findings)
		}
	case []any:
		for _, item := range val {
			scanAny(item, scanner, findings)
		}
	}
}

func redactAny(v any, scanner PayloadScanner) (any, []DLPFinding, bool) {
	switch val := v.(type) {
	case string:
		if val == "" {
			return val, nil, false
		}
		redacted, f := scanner.RedactPayload(val)
		return redacted, f, redacted != val
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(val))
		var all []DLPFinding
		changed := false
		for _, k := range keys {
			nv, f, c := redactAny(val[k], scanner)
			out[k] = nv
			all = append(all, f...)
			if c {
				changed = true
			}
		}
		return out, all, changed
	case []any:
		out := make([]any, len(val))
		var all []DLPFinding
		changed := false
		for i, item := range val {
			nv, f, c := redactAny(item, scanner)
			out[i] = nv
			all = append(all, f...)
			if c {
				changed = true
			}
		}
		return out, all, changed
	default:
		return v, nil, false
	}
}

func severityRank(s policy.Severity) int {
	switch s {
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

func maxDLPFindingSeverity(findings []DLPFinding) policy.Severity {
	best := policy.SeverityInfo
	for _, f := range findings {
		if severityRank(f.Severity) > severityRank(best) {
			best = f.Severity
		}
	}
	return best
}

func maxPoisonSeverity(findings []PoisonFinding) policy.Severity {
	best := policy.SeverityInfo
	for _, f := range findings {
		if severityRank(f.Severity) > severityRank(best) {
			best = f.Severity
		}
	}
	return best
}

// readFrame auto-detects and reads a single JSON-RPC message framed either as
// NDJSON (newline-delimited) or LSP-style Content-Length headers.
func readFrame(br *bufio.Reader) ([]byte, frameMode, error) {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return nil, frameUnknown, err
		}
		if b[0] == '\r' || b[0] == '\n' || b[0] == ' ' || b[0] == '\t' {
			_, _ = br.ReadByte()
			continue
		}

		// NDJSON frame (starts directly with JSON object or array).
		if b[0] == '{' || b[0] == '[' {
			line, err := br.ReadBytes('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, frameUnknown, err
			}
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 {
				if errors.Is(err, io.EOF) {
					return nil, frameUnknown, io.EOF
				}
				continue
			}
			return trimmed, frameNDJSON, nil
		}

		// Content-Length header framing.
		contentLength := -1
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, frameUnknown, err
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break
			}
			if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
				key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
				val := strings.TrimSpace(trimmed[idx+1:])
				if key == "content-length" {
					n, convErr := strconv.Atoi(val)
					if convErr != nil || n < 0 || n > maxFrameBytes {
						return nil, frameUnknown, fmt.Errorf("invalid Content-Length header %q", val)
					}
					contentLength = n
				}
			}
		}

		if contentLength < 0 {
			return nil, frameUnknown, fmt.Errorf("missing Content-Length header in framed JSON-RPC message")
		}
		buf := make([]byte, contentLength)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, frameUnknown, err
		}
		return buf, frameContentLength, nil
	}
}

func writeFrame(w io.Writer, mu *sync.Mutex, payload []byte, mode frameMode) error {
	mu.Lock()
	defer mu.Unlock()

	if mode == frameContentLength {
		header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
		if _, err := io.WriteString(w, header); err != nil {
			return err
		}
		_, err := w.Write(payload)
		return err
	}

	// Default to NDJSON (compact single-line JSON + '\n').
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
