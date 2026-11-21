package policy

import "time"

// CurrentVersion is the canonical YAML/JSON schema version for MCPGate policies.
const CurrentVersion = "mcpgate/v1"

// Action defines how MCPGate handles a matched request, tool call, or finding.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionDeny   Action = "deny"
	ActionBlock  Action = "block"
	ActionRedact Action = "redact"
	ActionWarn   Action = "warn"
	ActionPrompt Action = "prompt"
)

// Severity defines standardized security severity levels aligned with SARIF 2.1.0.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Policy is the root zero-trust configuration for MCPGate.
type Policy struct {
	Version    string           `yaml:"version" json:"version"`
	Name       string           `yaml:"name,omitempty" json:"name,omitempty"`
	Preset     string           `yaml:"preset,omitempty" json:"preset,omitempty"`
	Filesystem FilesystemPolicy `yaml:"filesystem" json:"filesystem"`
	Network    NetworkPolicy    `yaml:"network" json:"network"`
	DLP        DLPPolicy        `yaml:"dlp" json:"dlp"`
	MCP        MCPPolicy        `yaml:"mcp" json:"mcp"`
	Sandbox    SandboxPolicy    `yaml:"sandbox" json:"sandbox"`
	Audit      AuditPolicy      `yaml:"audit" json:"audit"`
}

// FilesystemPolicy constrains filesystem arguments and OS sandbox access.
type FilesystemPolicy struct {
	AllowPaths             []string `yaml:"allow_paths,omitempty" json:"allow_paths,omitempty"`
	DenyPaths              []string `yaml:"deny_paths,omitempty" json:"deny_paths,omitempty"`
	ReadOnly               bool     `yaml:"read_only,omitempty" json:"read_only,omitempty"`
	BlockSensitiveDefaults bool     `yaml:"block_sensitive_defaults" json:"block_sensitive_defaults"`
}

// NetworkPolicy governs outbound HTTP/HTTPS egress and SSRF controls.
type NetworkPolicy struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	AllowDomains       []string `yaml:"allow_domains,omitempty" json:"allow_domains,omitempty"`
	DenyDomains        []string `yaml:"deny_domains,omitempty" json:"deny_domains,omitempty"`
	AllowPorts         []int    `yaml:"allow_ports,omitempty" json:"allow_ports,omitempty"`
	BlockPrivateIPs    bool     `yaml:"block_private_ips" json:"block_private_ips"`
	BlockCloudMetadata bool     `yaml:"block_cloud_metadata" json:"block_cloud_metadata"`
	InspectTLS         bool     `yaml:"inspect_tls,omitempty" json:"inspect_tls,omitempty"`
}

// CustomDLPPattern defines a user-supplied regular expression secret rule.
type CustomDLPPattern struct {
	ID       string   `yaml:"id" json:"id"`
	Name     string   `yaml:"name" json:"name"`
	Pattern  string   `yaml:"pattern" json:"pattern"`
	Severity Severity `yaml:"severity,omitempty" json:"severity,omitempty"`
}

// DLPPolicy configures live secret and PII exfiltration scanning.
type DLPPolicy struct {
	Enabled        bool               `yaml:"enabled" json:"enabled"`
	Action         Action             `yaml:"action" json:"action"` // block | redact | warn
	LoadDotEnv     bool               `yaml:"load_dotenv" json:"load_dotenv"`
	DotEnvPaths    []string           `yaml:"dotenv_paths,omitempty" json:"dotenv_paths,omitempty"`
	CustomPatterns []CustomDLPPattern `yaml:"custom_patterns,omitempty" json:"custom_patterns,omitempty"`
}

// MCPPolicy governs live JSON-RPC tool authorization, schema lock, and circuit breaking.
type MCPPolicy struct {
	DefaultToolAction    Action   `yaml:"default_tool_action" json:"default_tool_action"` // allow | deny | prompt
	AllowTools           []string `yaml:"allow_tools,omitempty" json:"allow_tools,omitempty"`
	DenyTools            []string `yaml:"deny_tools,omitempty" json:"deny_tools,omitempty"`
	PromptTools          []string `yaml:"prompt_tools,omitempty" json:"prompt_tools,omitempty"`
	BlockPoisoning       bool     `yaml:"block_poisoning" json:"block_poisoning"`
	QuarantinePoisoned   bool     `yaml:"quarantine_poisoned" json:"quarantine_poisoned"`
	LockfilePath         string   `yaml:"lockfile_path,omitempty" json:"lockfile_path,omitempty"`
	LockMode             string   `yaml:"lock_mode,omitempty" json:"lock_mode,omitempty"` // off | warn | enforce | update
	MaxCallsPerMinute    int      `yaml:"max_calls_per_minute,omitempty" json:"max_calls_per_minute,omitempty"`
	MaxConsecutiveErrors int      `yaml:"max_consecutive_errors,omitempty" json:"max_consecutive_errors,omitempty"`
	MaxIdenticalCalls    int      `yaml:"max_identical_calls,omitempty" json:"max_identical_calls,omitempty"`
}

// SandboxPolicy controls OS-level process, memory, and environment containment.
type SandboxPolicy struct {
	CleanEnv       bool     `yaml:"clean_env" json:"clean_env"`
	PassEnv        []string `yaml:"pass_env,omitempty" json:"pass_env,omitempty"`
	WorkDir        string   `yaml:"work_dir,omitempty" json:"work_dir,omitempty"`
	MaxMemoryMB    int      `yaml:"max_memory_mb,omitempty" json:"max_memory_mb,omitempty"`
	MaxProcesses   int      `yaml:"max_processes,omitempty" json:"max_processes,omitempty"`
	UseLandlock    bool     `yaml:"use_landlock,omitempty" json:"use_landlock,omitempty"`
	UseSeatbelt    bool     `yaml:"use_seatbelt,omitempty" json:"use_seatbelt,omitempty"`
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

// AuditPolicy configures structured JSONL audit logging.
type AuditPolicy struct {
	LogPath    string `yaml:"log_path,omitempty" json:"log_path,omitempty"`
	LogAllowed bool   `yaml:"log_allowed,omitempty" json:"log_allowed,omitempty"`
}

// SecurityEvent is the unified structured JSONL audit record emitted by all MCPGate subsystems
// and compatible with ToolPrune v1.4.0 security event logs.
type SecurityEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	SessionID string            `json:"session_id,omitempty"`
	Category  string            `json:"category"` // dlp|egress|ssrf|poisoning|rugpull|path|tool_policy|breaker|sandbox|audit
	Severity  Severity          `json:"severity"`
	Action    string            `json:"action"` // blocked|quarantined|redacted|warned|allowed|prompted
	RuleID    string            `json:"rule_id"`
	Server    string            `json:"server,omitempty"`
	Tool      string            `json:"tool,omitempty"`
	Target    string            `json:"target,omitempty"`
	Message   string            `json:"message"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Decision captures the outcome of evaluating a policy check.
type Decision struct {
	Action   Action   `json:"action"`
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
}

