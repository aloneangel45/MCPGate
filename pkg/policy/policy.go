package policy

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultSensitiveSegments are credential and key locations blocked by default when
// Filesystem.BlockSensitiveDefaults is enabled.
var DefaultSensitiveSegments = []string{
	".ssh",
	".aws",
	".gnupg",
	".kube",
	".docker/config.json",
	".npmrc",
	".pypirc",
	".netrc",
	".git-credentials",
	".env",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"credentials.json",
	"service-account",
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"appdata/roaming/gcloud",
	"appdata/roaming/aws",
	"appdata/local/microsoft/credentials",
	"library/keychains",
}

// Preset returns a built-in zero-trust security policy by name:
// "strict", "balanced", "readonly", or "airgapped".
func Preset(name string) (*Policy, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "balanced":
		return &Policy{
			Version: CurrentVersion,
			Name:    "balanced",
			Preset:  "balanced",
			Filesystem: FilesystemPolicy{
				BlockSensitiveDefaults: true,
			},
			Network: NetworkPolicy{
				Enabled:            true,
				AllowPorts:         []int{80, 443},
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
			DLP: DLPPolicy{
				Enabled:    true,
				Action:     ActionBlock,
				LoadDotEnv: true,
			},
			MCP: MCPPolicy{
				DefaultToolAction:    ActionAllow,
				DenyTools:            []string{"*delete_all*", "*drop_database*", "*format_disk*"},
				PromptTools:          []string{"*exec*", "*shell*", "*bash*", "*powershell*", "*run_command*", "*write_file*", "*delete*"},
				BlockPoisoning:       true,
				QuarantinePoisoned:   true,
				LockMode:             "warn",
				MaxCallsPerMinute:    120,
				MaxConsecutiveErrors: 12,
				MaxIdenticalCalls:    10,
			},
			Sandbox: SandboxPolicy{
				CleanEnv:     true,
				PassEnv:      []string{"PATH", "HOME", "USER", "USERPROFILE", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC", "LANG", "LC_ALL", "TERM"},
				MaxMemoryMB:  1024,
				MaxProcesses: 64,
				UseLandlock:  true,
				UseSeatbelt:  true,
			},
		}, nil

	case "strict":
		return &Policy{
			Version: CurrentVersion,
			Name:    "strict",
			Preset:  "strict",
			Filesystem: FilesystemPolicy{
				AllowPaths:             []string{"."},
				BlockSensitiveDefaults: true,
			},
			Network: NetworkPolicy{
				Enabled:            true,
				AllowDomains:       []string{}, // deny-by-default unless explicitly allowlisted
				AllowPorts:         []int{443},
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
			DLP: DLPPolicy{
				Enabled:    true,
				Action:     ActionBlock,
				LoadDotEnv: true,
			},
			MCP: MCPPolicy{
				DefaultToolAction:    ActionDeny,
				AllowTools:           []string{"read_*", "list_*", "get_*", "search_*", "inspect_*"},
				PromptTools:          []string{"write_*", "edit_*", "create_*"},
				BlockPoisoning:       true,
				QuarantinePoisoned:   true,
				LockMode:             "enforce",
				MaxCallsPerMinute:    60,
				MaxConsecutiveErrors: 6,
				MaxIdenticalCalls:    5,
			},
			Sandbox: SandboxPolicy{
				CleanEnv:     true,
				PassEnv:      []string{"PATH", "HOME", "USER", "USERPROFILE", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC"},
				MaxMemoryMB:  512,
				MaxProcesses: 32,
				UseLandlock:  true,
				UseSeatbelt:  true,
			},
		}, nil

	case "readonly":
		return &Policy{
			Version: CurrentVersion,
			Name:    "readonly",
			Preset:  "readonly",
			Filesystem: FilesystemPolicy{
				AllowPaths:             []string{"."},
				ReadOnly:               true,
				BlockSensitiveDefaults: true,
			},
			Network: NetworkPolicy{
				Enabled:            false,
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
			DLP: DLPPolicy{
				Enabled:    true,
				Action:     ActionBlock,
				LoadDotEnv: true,
			},
			MCP: MCPPolicy{
				DefaultToolAction:    ActionDeny,
				AllowTools:           []string{"read*", "list*", "get*", "search*", "find*", "inspect*", "diff*", "status*"},
				DenyTools:            []string{"*write*", "*edit*", "*delete*", "*remove*", "*exec*", "*shell*", "*run*", "*create*", "*update*", "*post*", "*put*"},
				BlockPoisoning:       true,
				QuarantinePoisoned:   true,
				LockMode:             "enforce",
				MaxCallsPerMinute:    90,
				MaxConsecutiveErrors: 8,
				MaxIdenticalCalls:    8,
			},
			Sandbox: SandboxPolicy{
				CleanEnv:     true,
				PassEnv:      []string{"PATH", "HOME", "USER", "USERPROFILE", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC"},
				MaxMemoryMB:  512,
				MaxProcesses: 24,
				UseLandlock:  true,
				UseSeatbelt:  true,
			},
		}, nil

	case "airgapped":
		return &Policy{
			Version: CurrentVersion,
			Name:    "airgapped",
			Preset:  "airgapped",
			Filesystem: FilesystemPolicy{
				AllowPaths:             []string{"."},
				BlockSensitiveDefaults: true,
			},
			Network: NetworkPolicy{
				Enabled:            false,
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
			DLP: DLPPolicy{
				Enabled:    true,
				Action:     ActionBlock,
				LoadDotEnv: true,
			},
			MCP: MCPPolicy{
				DefaultToolAction:    ActionAllow,
				DenyTools:            []string{"*fetch*", "*http*", "*curl*", "*download*", "*webhook*", "*upload*"},
				BlockPoisoning:       true,
				QuarantinePoisoned:   true,
				LockMode:             "enforce",
				MaxCallsPerMinute:    90,
				MaxConsecutiveErrors: 8,
				MaxIdenticalCalls:    8,
			},
			Sandbox: SandboxPolicy{
				CleanEnv:     true,
				PassEnv:      []string{"PATH", "HOME", "USER", "USERPROFILE", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC"},
				MaxMemoryMB:  512,
				MaxProcesses: 32,
				UseLandlock:  true,
				UseSeatbelt:  true,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown policy preset %q (expected strict, balanced, readonly, or airgapped)", name)
	}
}

// LoadFile reads, parses, applies preset defaults if requested, and validates a policy YAML file.
func LoadFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", filePath, err)
	}
	return ParseYAML(data)
}

// ParseYAML parses YAML policy bytes, seeding from a named preset when specified.
func ParseYAML(data []byte) (*Policy, error) {
	var peek struct {
		Preset string `yaml:"preset"`
	}
	if err := yaml.Unmarshal(data, &peek); err != nil {
		return nil, fmt.Errorf("parse policy yaml: %w", err)
	}
	var base *Policy
	if strings.TrimSpace(peek.Preset) != "" {
		p, err := Preset(peek.Preset)
		if err != nil {
			return nil, err
		}
		base = p
	} else {
		base, _ = Preset("balanced")
	}
	if err := yaml.Unmarshal(data, base); err != nil {
		return nil, fmt.Errorf("unmarshal policy yaml: %w", err)
	}
	if strings.TrimSpace(base.Version) == "" {
		base.Version = CurrentVersion
	}
	if err := base.Validate(); err != nil {
		return nil, err
	}
	return base, nil
}

// Validate checks policy invariants and rejects malformed settings.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("policy is nil")
	}
	switch p.DLP.Action {
	case "", ActionBlock, ActionRedact, ActionWarn:
	default:
		return fmt.Errorf("invalid dlp.action %q (expected block, redact, or warn)", p.DLP.Action)
	}
	if p.DLP.Action == "" {
		p.DLP.Action = ActionBlock
	}
	switch p.MCP.DefaultToolAction {
	case "", ActionAllow, ActionDeny, ActionPrompt:
	default:
		return fmt.Errorf("invalid mcp.default_tool_action %q (expected allow, deny, or prompt)", p.MCP.DefaultToolAction)
	}
	if p.MCP.DefaultToolAction == "" {
		p.MCP.DefaultToolAction = ActionAllow
	}
	switch strings.ToLower(strings.TrimSpace(p.MCP.LockMode)) {
	case "", "off", "warn", "enforce", "update":
	default:
		return fmt.Errorf("invalid mcp.lock_mode %q (expected off, warn, enforce, or update)", p.MCP.LockMode)
	}
	for _, port := range p.Network.AllowPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid network.allow_ports entry: %d", port)
		}
	}
	if p.MCP.MaxCallsPerMinute < 0 || p.MCP.MaxConsecutiveErrors < 0 || p.MCP.MaxIdenticalCalls < 0 {
		return fmt.Errorf("circuit breaker limits cannot be negative")
	}
	if p.Sandbox.MaxMemoryMB < 0 || p.Sandbox.MaxProcesses < 0 || p.Sandbox.TimeoutSeconds < 0 {
		return fmt.Errorf("sandbox limits cannot be negative")
	}
	return nil
}

// ToYAML serializes the policy into clean YAML.
func (p *Policy) ToYAML() ([]byte, error) {
	return yaml.Marshal(p)
}

// EvaluateTool decides whether an MCP tool invocation is allowed, denied, or requires confirmation.
// Precedence: explicit DenyTools > PromptTools > AllowTools > DefaultToolAction.
func (p *Policy) EvaluateTool(toolName string) Decision {
	name := strings.TrimSpace(toolName)
	lower := strings.ToLower(name)
	for _, pat := range p.MCP.DenyTools {
		if globMatch(strings.ToLower(pat), lower) {
			return Decision{
				Action:   ActionDeny,
				RuleID:   "MCP07-TOOL-DENY",
				Severity: SeverityHigh,
				Reason:   fmt.Sprintf("tool %q matches deny pattern %q", name, pat),
			}
		}
	}
	for _, pat := range p.MCP.PromptTools {
		if globMatch(strings.ToLower(pat), lower) {
			return Decision{
				Action:   ActionPrompt,
				RuleID:   "MCP07-TOOL-PROMPT",
				Severity: SeverityMedium,
				Reason:   fmt.Sprintf("tool %q requires explicit approval (pattern %q)", name, pat),
			}
		}
	}
	for _, pat := range p.MCP.AllowTools {
		if globMatch(strings.ToLower(pat), lower) {
			return Decision{
				Action:   ActionAllow,
				RuleID:   "MCP07-TOOL-ALLOW",
				Severity: SeverityInfo,
				Reason:   fmt.Sprintf("tool %q matches allow pattern %q", name, pat),
			}
		}
	}
	if p.MCP.DefaultToolAction == ActionDeny {
		return Decision{
			Action:   ActionDeny,
			RuleID:   "MCP07-TOOL-DEFAULT-DENY",
			Severity: SeverityHigh,
			Reason:   fmt.Sprintf("tool %q denied by default zero-trust policy", name),
		}
	}
	if p.MCP.DefaultToolAction == ActionPrompt {
		return Decision{
			Action:   ActionPrompt,
			RuleID:   "MCP07-TOOL-DEFAULT-PROMPT",
			Severity: SeverityMedium,
			Reason:   fmt.Sprintf("tool %q requires approval under default prompt policy", name),
		}
	}
	return Decision{
		Action:   ActionAllow,
		RuleID:   "MCP07-TOOL-DEFAULT-ALLOW",
		Severity: SeverityInfo,
		Reason:   fmt.Sprintf("tool %q allowed", name),
	}
}

// EvaluatePath validates a filesystem path argument against traversal escapes,
// default sensitive credential paths, DenyPaths, and AllowPaths.
func (p *Policy) EvaluatePath(rawPath, workDir string) Decision {
	candidate := strings.TrimSpace(rawPath)
	if candidate == "" {
		return Decision{Action: ActionAllow, RuleID: "MCP05-PATH-OK", Severity: SeverityInfo}
	}

	normRaw := strings.ToLower(strings.ReplaceAll(candidate, "\\", "/"))
	expanded := expandTilde(candidate)
	if !filepath.IsAbs(expanded) && workDir != "" {
		expanded = filepath.Join(workDir, expanded)
	}
	cleaned := filepath.Clean(expanded)
	normClean := strings.ToLower(strings.ReplaceAll(cleaned, "\\", "/"))

	// 1. Sensitive default credentials guard (checked on both raw & resolved paths).
	if p.Filesystem.BlockSensitiveDefaults {
		for _, seg := range DefaultSensitiveSegments {
			if matchesSensitiveSegment(normRaw, seg) || matchesSensitiveSegment(normClean, seg) {
				return Decision{
					Action:   ActionDeny,
					RuleID:   "MCP05-SENSITIVE-PATH",
					Severity: SeverityCritical,
					Reason:   fmt.Sprintf("path %q targets protected sensitive credential location (%s)", candidate, seg),
				}
			}
		}
	}

	// 2. Explicit DenyPaths check.
	for _, deny := range p.Filesystem.DenyPaths {
		if pathMatchesRule(candidate, cleaned, deny, workDir) {
			return Decision{
				Action:   ActionDeny,
				RuleID:   "MCP05-PATH-DENY",
				Severity: SeverityHigh,
				Reason:   fmt.Sprintf("path %q matches deny rule %q", candidate, deny),
			}
		}
	}

	// 3. Explicit AllowPaths confinement (blocks traversal outside allowlisted roots).
	if len(p.Filesystem.AllowPaths) > 0 {
		allowed := false
		for _, allow := range p.Filesystem.AllowPaths {
			if pathWithinRoot(cleaned, allow, workDir) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Decision{
				Action:   ActionDeny,
				RuleID:   "MCP05-PATH-TRAVERSAL",
				Severity: SeverityHigh,
				Reason:   fmt.Sprintf("path %q escapes allowlisted roots %v", candidate, p.Filesystem.AllowPaths),
			}
		}
	}

	return Decision{Action: ActionAllow, RuleID: "MCP05-PATH-OK", Severity: SeverityInfo, Reason: "path allowed"}
}

// EvaluateDomain validates an outbound target host and port against NetworkPolicy.
func (p *Policy) EvaluateDomain(host string, port int) Decision {
	cleanHost := strings.ToLower(strings.TrimSpace(host))
	cleanHost = strings.TrimSuffix(cleanHost, ".")
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = strings.Trim(h, "[]")
	} else {
		cleanHost = strings.Trim(cleanHost, "[]")
	}

	if !p.Network.Enabled {
		return Decision{
			Action:   ActionDeny,
			RuleID:   "MCP06-EGRESS-AIRGAPPED",
			Severity: SeverityHigh,
			Reason:   fmt.Sprintf("outbound network disabled by policy (target %s)", cleanHost),
		}
	}

	if len(p.Network.AllowPorts) > 0 && port > 0 {
		portOK := false
		for _, ap := range p.Network.AllowPorts {
			if ap == port {
				portOK = true
				break
			}
		}
		if !portOK {
			return Decision{
				Action:   ActionDeny,
				RuleID:   "MCP06-EGRESS-PORT-DENY",
				Severity: SeverityMedium,
				Reason:   fmt.Sprintf("outbound port %d not in allow_ports %v", port, p.Network.AllowPorts),
			}
		}
	}

	// Explicit DenyDomains always wins.
	for _, pat := range p.Network.DenyDomains {
		if domainMatch(pat, cleanHost) {
			return Decision{
				Action:   ActionDeny,
				RuleID:   "MCP06-EGRESS-DENY",
				Severity: SeverityHigh,
				Reason:   fmt.Sprintf("domain %q matches deny rule %q", cleanHost, pat),
			}
		}
	}

	// In strict mode or whenever AllowDomains is configured, enforce allowlist.
	if len(p.Network.AllowDomains) > 0 || strings.EqualFold(p.Preset, "strict") {
		for _, pat := range p.Network.AllowDomains {
			if domainMatch(pat, cleanHost) {
				return Decision{
					Action:   ActionAllow,
					RuleID:   "MCP06-EGRESS-ALLOW",
					Severity: SeverityInfo,
					Reason:   fmt.Sprintf("domain %q matched allowlist %q", cleanHost, pat),
				}
			}
		}
		return Decision{
			Action:   ActionDeny,
			RuleID:   "MCP06-EGRESS-NOT-ALLOWLISTED",
			Severity: SeverityHigh,
			Reason:   fmt.Sprintf("domain %q is not in allow_domains", cleanHost),
		}
	}

	return Decision{Action: ActionAllow, RuleID: "MCP06-EGRESS-ALLOW", Severity: SeverityInfo, Reason: "domain allowed"}
}

func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~/"), "~\\"))
		}
	}
	return p
}

func matchesSensitiveSegment(normPath, seg string) bool {
	seg = strings.ToLower(strings.TrimSpace(seg))
	if seg == "" {
		return false
	}
	if strings.HasPrefix(seg, "/") {
		return normPath == seg || strings.HasPrefix(normPath, seg+"/")
	}
	if strings.Contains(seg, "/") {
		return strings.Contains(normPath, "/"+seg) || normPath == seg || strings.HasPrefix(normPath, seg+"/")
	}
	parts := strings.Split(normPath, "/")
	for _, part := range parts {
		if part == seg {
			return true
		}
		// Match .env.local, .env.production, service-account-prod.json, id_rsa.pub etc.
		if seg == ".env" && strings.HasPrefix(part, ".env.") {
			return true
		}
		if (seg == "id_rsa" || seg == "id_ed25519" || seg == "id_ecdsa" || seg == "service-account") && strings.HasPrefix(part, seg) {
			return true
		}
	}
	return false
}

func pathMatchesRule(rawPath, cleanedPath, rule, workDir string) bool {
	if strings.ContainsAny(rule, "*?[") {
		normRaw := strings.ToLower(strings.ReplaceAll(rawPath, "\\", "/"))
		normClean := strings.ToLower(strings.ReplaceAll(cleanedPath, "\\", "/"))
		normRule := strings.ToLower(strings.ReplaceAll(rule, "\\", "/"))
		return globMatch(normRule, normRaw) || globMatch(normRule, normClean) || globMatch(normRule, path.Base(normClean))
	}
	return pathWithinRoot(cleanedPath, rule, workDir)
}

func pathWithinRoot(cleanedTarget, root, workDir string) bool {
	r := expandTilde(strings.TrimSpace(root))
	if r == "" {
		return false
	}
	if !filepath.IsAbs(r) && workDir != "" {
		r = filepath.Join(workDir, r)
	}
	absRoot, err1 := filepath.Abs(r)
	absTarget, err2 := filepath.Abs(cleanedTarget)
	if err1 != nil || err2 != nil {
		return false
	}
	// Resolve symlinks when paths exist to prevent symlink escape attacks.
	if realRoot, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = realRoot
	}
	if realTarget, err := filepath.EvalSymlinks(absTarget); err == nil {
		absTarget = realTarget
	}
	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func domainMatch(pattern, host string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	pat = strings.TrimSuffix(pat, ".")
	if pat == "" || host == "" {
		return false
	}
	if pat == "*" {
		return true
	}
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:] // ".example.com"
		base := pat[2:]   // "example.com"
		return host == base || strings.HasSuffix(host, suffix)
	}
	return host == pat
}

// globMatch implements case-sensitive wildcard matching supporting '*' and '?'.
func globMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	px, sx := 0, 0
	starIdx, matchIdx := -1, 0
	for sx < len(s) {
		if px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]) {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			starIdx = px
			matchIdx = sx
			px++
		} else if starIdx != -1 {
			px = starIdx + 1
			matchIdx++
			sx = matchIdx
		} else {
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

