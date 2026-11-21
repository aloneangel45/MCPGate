package mcpproxy

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// ToolDefinition represents an MCP tool entry returned by tools/list.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

// PoisonFinding describes a single tool-poisoning indicator found in an MCP tool definition.
type PoisonFinding struct {
	RuleID      string          `json:"rule_id"`
	Category    string          `json:"category"` // prompt_injection | exfiltration | unicode_spoofing | encoded_payload | shell_smuggling
	Severity    policy.Severity `json:"severity"`
	Field       string          `json:"field"`
	Evidence    string          `json:"evidence"`
	Description string          `json:"description"`
}

type poisonPattern struct {
	ruleID      string
	category    string
	severity    policy.Severity
	description string
	re          *regexp.Regexp
}

var (
	promptInjectionPatterns = []poisonPattern{
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "prompt_injection",
			severity:    policy.SeverityCritical,
			description: "embedded XML/tag prompt-injection directive",
			re:          regexp.MustCompile(`(?i)<\s*/?\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|HIDDEN|SECRET|OVERRIDE)(?:\s+[^>]*)?\s*/?\s*>`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "prompt_injection",
			severity:    policy.SeverityCritical,
			description: "instruction-override prompt injection phrase",
			re:          regexp.MustCompile(`(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|disregard\s+(?:all\s+)?(?:prior|previous|above))\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "prompt_injection",
			severity:    policy.SeverityCritical,
			description: "coercive pre-execution directive in tool metadata",
			re:          regexp.MustCompile(`(?i)\b(?:you\s+must\s+(?:first|always|never)|before\s+(?:calling|using|invoking|running)\s+this\s+tool)\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "prompt_injection",
			severity:    policy.SeverityCritical,
			description: "stealth instruction hiding actions from the user",
			re:          regexp.MustCompile(`(?i)\b(?:do\s+not\s+(?:mention|tell|show|inform|reveal|display)\s+(?:this\s+)?(?:to\s+)?the\s+user|hide\s+(?:this|the\s+output|these\s+instructions?)\s+from\s+the\s+user|never\s+(?:mention|tell|reveal|inform)\s+(?:this\s+)?(?:to\s+)?the\s+user)\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "prompt_injection",
			severity:    policy.SeverityHigh,
			description: "covert execution directive ('silently')",
			re:          regexp.MustCompile(`(?i)\bsilently\b`),
		},
	}

	exfilPatterns = []poisonPattern{
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "exfiltration",
			severity:    policy.SeverityCritical,
			description: "references SSH private keys or ~/.ssh directory",
			re:          regexp.MustCompile(`(?i)(?:~/\.ssh|\.ssh[/\\]|id_rsa\b|id_ed25519\b|id_ecdsa\b)`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "exfiltration",
			severity:    policy.SeverityCritical,
			description: "references AWS credentials path (~/.aws)",
			re:          regexp.MustCompile(`(?i)(?:~/\.aws|\.aws[/\\]credentials)`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "exfiltration",
			severity:    policy.SeverityCritical,
			description: "references .env secrets file",
			re:          regexp.MustCompile(`(?i)(?:^|[\s"'(/\\])\.env(?:\.[a-z0-9_-]+)?(?:$|[\s"'/),;:])`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "exfiltration",
			severity:    policy.SeverityCritical,
			description: "references system password/shadow files",
			re:          regexp.MustCompile(`(?i)/etc/(?:passwd|shadow|sudoers)\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "exfiltration",
			severity:    policy.SeverityCritical,
			description: "references credential or token configuration file",
			re:          regexp.MustCompile(`(?i)(?:credentials\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.kube[/\\]config|\.docker[/\\]config\.json)\b`),
		},
	}

	shellSmugglingPatterns = []poisonPattern{
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "shell_smuggling",
			severity:    policy.SeverityCritical,
			description: "remote script pipe-to-shell command (curl/wget | sh)",
			re:          regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{1,200}\|\s*(?:ba|z|da|a)?sh\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "shell_smuggling",
			severity:    policy.SeverityCritical,
			description: "encoded PowerShell execution command",
			re:          regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\b[^\n]{0,120}\s-(?:e|ec|enc|encodedcommand)\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "shell_smuggling",
			severity:    policy.SeverityCritical,
			description: "base64 decode piped to shell",
			re:          regexp.MustCompile(`(?i)\bbase64\s+(?:-d|--decode)\s*\|\s*(?:ba|z|da|a)?sh\b`),
		},
		{
			ruleID:      "MCP01-TOOL-POISONING",
			category:    "shell_smuggling",
			severity:    policy.SeverityCritical,
			description: "reverse shell command pattern",
			re:          regexp.MustCompile(`(?i)(?:bash\s+-i\s+>&\s*/dev/tcp/|nc\s+(?:-e|-c)\s+/bin/)`),
		},
	}

	base64BlobRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{64,}={0,2})(?:$|[^A-Za-z0-9+/=])`)
)

// ScanToolPoisoning inspects an MCP tool's name, description, inputSchema, and annotations
// for prompt injection, credential exfiltration instructions, BiDi/invisible Unicode spoofing,
// embedded base64 payloads, and shell-smuggling directives.
func ScanToolPoisoning(tool ToolDefinition) []PoisonFinding {
	var findings []PoisonFinding
	findings = append(findings, ScanTextPoisoning("name", tool.Name)...)
	findings = append(findings, ScanTextPoisoning("description", tool.Description)...)
	if len(tool.InputSchema) > 0 {
		scanSchemaValue("inputSchema", tool.InputSchema, &findings)
	}
	if len(tool.Annotations) > 0 {
		scanSchemaValue("annotations", tool.Annotations, &findings)
	}
	return findings
}

func scanSchemaValue(path string, v any, out *[]PoisonFinding) {
	switch val := v.(type) {
	case string:
		*out = append(*out, ScanTextPoisoning(path, val)...)
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childPath := path + "." + k
			*out = append(*out, ScanTextPoisoning(childPath+"(key)", k)...)
			scanSchemaValue(childPath, val[k], out)
		}
	case []any:
		for i, item := range val {
			scanSchemaValue(fmt.Sprintf("%s[%d]", path, i), item, out)
		}
	}
}

// ScanTextPoisoning scans a single text field for poisoning indicators, including
// HTML-entity obfuscated tags and invisible Unicode character smuggling.
func ScanTextPoisoning(field, text string) []PoisonFinding {
	if text == "" {
		return nil
	}
	var findings []PoisonFinding

	// Build normalized text variants: raw, HTML-entity decoded (up to 2 passes),
	// and invisible-Unicode-stripped so obfuscation cannot hide tags or keywords.
	variants := []string{text}
	unescaped := text
	for pass := 0; pass < 2; pass++ {
		next := html.UnescapeString(unescaped)
		if next == unescaped {
			break
		}
		unescaped = next
	}
	if unescaped != text {
		variants = append(variants, unescaped)
	}
	stripped := stripSuspiciousUnicode(unescaped)
	if stripped != unescaped && stripped != text {
		variants = append(variants, stripped)
	}

	seen := make(map[string]struct{})
	checkPatterns := func(patterns []poisonPattern) {
		for _, pat := range patterns {
			key := pat.category + "|" + pat.description
			if _, dup := seen[key]; dup {
				continue
			}
			for _, candidate := range variants {
				if m := pat.re.FindString(candidate); m != "" {
					seen[key] = struct{}{}
					findings = append(findings, PoisonFinding{
						RuleID:      pat.ruleID,
						Category:    pat.category,
						Severity:    pat.severity,
						Field:       field,
						Evidence:    truncateEvidence(strings.TrimSpace(m), 96),
						Description: pat.description,
					})
					break
				}
			}
		}
	}

	checkPatterns(promptInjectionPatterns)
	checkPatterns(exfilPatterns)
	checkPatterns(shellSmugglingPatterns)

	if codepoints := findSuspiciousUnicode(text); len(codepoints) > 0 {
		findings = append(findings, PoisonFinding{
			RuleID:      "MCP01-TOOL-POISONING",
			Category:    "unicode_spoofing",
			Severity:    policy.SeverityHigh,
			Field:       field,
			Evidence:    strings.Join(codepoints, ","),
			Description: "invisible or bidirectional Unicode control/tag characters detected",
		})
	}

	if blobs := findSuspiciousBase64(text); len(blobs) > 0 {
		findings = append(findings, PoisonFinding{
			RuleID:      "MCP01-TOOL-POISONING",
			Category:    "encoded_payload",
			Severity:    policy.SeverityHigh,
			Field:       field,
			Evidence:    truncateEvidence(blobs[0], 64),
			Description: fmt.Sprintf("embedded large Base64 payload (%d chars)", len(blobs[0])),
		})
	}

	return findings
}

func stripSuspiciousUnicode(s string) string {
	hasAny := false
	for _, r := range s {
		if isSuspiciousUnicodeRune(r) {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !isSuspiciousUnicodeRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func findSuspiciousUnicode(s string) []string {
	seen := make(map[rune]struct{})
	var found []string
	for _, r := range s {
		if isSuspiciousUnicodeRune(r) {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				found = append(found, fmt.Sprintf("U+%04X", r))
				if len(found) >= 8 {
					break
				}
			}
		}
	}
	return found
}

func isSuspiciousUnicodeRune(r rune) bool {
	switch {
	case r == 0x00AD: // Soft hyphen (invisible word splitter)
		return true
	case r == 0x061C: // Arabic Letter Mark (BiDi control)
		return true
	case r >= 0x200B && r <= 0x200F: // Zero-width & directional marks
		return true
	case r >= 0x202A && r <= 0x202E: // BiDi embedding & override
		return true
	case r == 0x2060: // Word Joiner (invisible)
		return true
	case r >= 0x2066 && r <= 0x2069: // BiDi isolates
		return true
	case r == 0xFEFF: // Zero-Width No-Break Space / embedded BOM
		return true
	case r >= 0xE0000 && r <= 0xE007F: // Unicode Tag characters (invisible prompt smuggling)
		return true
	default:
		return false
	}
}

func findSuspiciousBase64(s string) []string {
	matches := base64BlobRE.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		tok := m[1]
		if len(tok) < 64 {
			continue
		}
		if looksLikeBase64Payload(tok) {
			out = append(out, tok)
		}
	}
	return out
}

func looksLikeBase64Payload(tok string) bool {
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range tok {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case r == '+' || r == '/' || r == '=':
			hasSymbol = true
		}
	}
	// Require character-class diversity to avoid flagging plain long English/identifier strings.
	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}
	return classes >= 3 || (hasSymbol && classes >= 2)
}

func truncateEvidence(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		runes := []rune(s)
		if maxLen < 0 {
			return ""
		}
		return string(runes[:maxLen])
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}
