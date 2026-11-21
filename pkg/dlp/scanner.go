package dlp

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// Finding describes a single secret or PII match detected by the DLP scanner.
// MatchPreview is always masked and never contains the raw secret.
type Finding struct {
	RuleID       string          `json:"rule_id"`
	Name         string          `json:"name"`
	Severity     policy.Severity `json:"severity"`
	MatchPreview string          `json:"match_preview"`
	SHA256Prefix string          `json:"sha256_prefix"`
	Offset       int             `json:"offset"`
	Length       int             `json:"length"`
}

type regexRule struct {
	ruleID      string
	name        string
	severity    policy.Severity
	re          *regexp.Regexp
	secretGroup int // 0 = full match, >0 = capture group containing the secret value
	validate    func(match string) bool
	priority    int // higher wins on overlapping spans
}

// Scanner inspects outbound text, tool arguments, and HTTP payloads for secrets and PII.
// A Scanner is immutable after construction and safe for concurrent use.
type Scanner struct {
	cfg           policy.DLPPolicy
	rules         []regexRule
	dotEnvSecrets []dotEnvSecret
}

var (
	base64TokenRE   = regexp.MustCompile(`[A-Za-z0-9+/_-]{12,}={0,2}`)
	urlEncodedRunRE = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~+-]){10,}`)
)

// NewScanner compiles all built-in and custom DLP rules and optionally fingerprints .env secrets.
func NewScanner(cfg policy.DLPPolicy, workDir string) (*Scanner, error) {
	rules := builtinRules()

	for i, cp := range cfg.CustomPatterns {
		pat := strings.TrimSpace(cp.Pattern)
		if pat == "" {
			return nil, fmt.Errorf("custom DLP pattern %d has empty regex", i)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile custom DLP pattern %q (%s): %w", cp.ID, cp.Name, err)
		}
		ruleID := strings.TrimSpace(cp.ID)
		if ruleID == "" {
			ruleID = fmt.Sprintf("MCP03-CUSTOM-%d", i+1)
		}
		name := strings.TrimSpace(cp.Name)
		if name == "" {
			name = ruleID
		}
		sev := cp.Severity
		if sev == "" {
			sev = policy.SeverityHigh
		}
		rules = append(rules, regexRule{
			ruleID:   ruleID,
			name:     name,
			severity: sev,
			re:       re,
			priority: 40,
		})
	}

	var dotEnv []dotEnvSecret
	if cfg.LoadDotEnv {
		dotEnv = loadDotEnvSecrets(cfg.DotEnvPaths, workDir)
	}

	return &Scanner{
		cfg:           cfg,
		rules:         rules,
		dotEnvSecrets: dotEnv,
	}, nil
}

// Enabled reports whether DLP scanning is active in the scanner's policy.
func (s *Scanner) Enabled() bool {
	return s != nil && s.cfg.Enabled
}

// Action returns the configured DLP enforcement action (defaulting to ActionBlock).
func (s *Scanner) Action() policy.Action {
	if s == nil || s.cfg.Action == "" {
		return policy.ActionBlock
	}
	return s.cfg.Action
}

// DotEnvCount returns the number of unique secret values fingerprinted from .env files.
func (s *Scanner) DotEnvCount() int {
	if s == nil {
		return 0
	}
	return len(s.dotEnvSecrets)
}

type rankedFinding struct {
	finding  Finding
	priority int
}

// Scan inspects text for built-in secret patterns, custom patterns, and fingerprinted .env leaks.
// Returned findings are sorted by Offset ascending and deduplicated across overlapping spans.
func (s *Scanner) Scan(text string) []Finding {
	if s == nil || !s.cfg.Enabled || text == "" {
		return nil
	}

	var raw []rankedFinding

	// 1. Live .env secret fingerprinting (highest priority: 100).
	if len(s.dotEnvSecrets) > 0 {
		raw = append(raw, s.scanDotEnv(text)...)
	}

	// 2. Built-in & custom regex rules.
	for _, rule := range s.rules {
		if rule.secretGroup > 0 {
			matches := rule.re.FindAllStringSubmatchIndex(text, -1)
			for _, idx := range matches {
				gStart := 2 * rule.secretGroup
				gEnd := gStart + 1
				if gEnd >= len(idx) || idx[gStart] < 0 || idx[gEnd] <= idx[gStart] {
					continue
				}
				start, end := idx[gStart], idx[gEnd]
				matched := text[start:end]
				if rule.validate != nil && !rule.validate(matched) {
					continue
				}
				raw = append(raw, rankedFinding{
					finding: Finding{
						RuleID:       rule.ruleID,
						Name:         rule.name,
						Severity:     rule.severity,
						MatchPreview: maskSecret(matched),
						SHA256Prefix: sha256HexPrefix(matched),
						Offset:       start,
						Length:       end - start,
					},
					priority: rule.priority,
				})
			}
			continue
		}

		matches := rule.re.FindAllStringIndex(text, -1)
		for _, idx := range matches {
			start, end := idx[0], idx[1]
			if end <= start {
				continue
			}
			matched := text[start:end]
			if rule.validate != nil && !rule.validate(matched) {
				continue
			}
			raw = append(raw, rankedFinding{
				finding: Finding{
					RuleID:       rule.ruleID,
					Name:         rule.name,
					Severity:     rule.severity,
					MatchPreview: maskSecret(matched),
					SHA256Prefix: sha256HexPrefix(matched),
					Offset:       start,
					Length:       end - start,
				},
				priority: rule.priority,
			})
		}
	}

	return resolveOverlaps(raw)
}

// Redact replaces every detected secret in text with [MCPGATE-REDACTED:<RuleID>].
func (s *Scanner) Redact(text string) (string, []Finding) {
	findings := s.Scan(text)
	if len(findings) == 0 {
		return text, nil
	}

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, f := range findings {
		if f.Offset < cursor || f.Offset+f.Length > len(text) {
			continue
		}
		b.WriteString(text[cursor:f.Offset])
		b.WriteString("[MCPGATE-REDACTED:")
		b.WriteString(f.RuleID)
		b.WriteByte(']')
		cursor = f.Offset + f.Length
	}
	b.WriteString(text[cursor:])
	return b.String(), findings
}

func (s *Scanner) scanDotEnv(text string) []rankedFinding {
	var out []rankedFinding

	for _, secret := range s.dotEnvSecrets {
		// Exact verbatim occurrences.
		out = append(out, findAllLiteral(text, secret.Value, secret, 100)...)

		// Precomputed base64 and URL-encoded representations.
		for _, variant := range secret.Variants {
			out = append(out, findAllLiteral(text, variant, secret, 95)...)
		}
	}

	// Detect secrets embedded inside larger base64-encoded blobs (e.g. base64("key=" + secret)).
	for _, loc := range base64TokenRE.FindAllStringIndex(text, -1) {
		tok := text[loc[0]:loc[1]]
		if len(tok) < 12 || len(tok) > 16384 {
			continue
		}
		decoded, ok := tryDecodeBase64(tok)
		if !ok || len(decoded) < minDotEnvSecretLen {
			continue
		}
		for _, secret := range s.dotEnvSecrets {
			if strings.Contains(decoded, secret.Value) {
				out = append(out, rankedFinding{
					finding: Finding{
						RuleID:       "MCP03-DOTENV-LEAK",
						Name:         fmt.Sprintf("DotEnv Secret Leak (%s, base64)", secret.Key),
						Severity:     policy.SeverityCritical,
						MatchPreview: maskSecret(secret.Value),
						SHA256Prefix: secret.SHA256Prefix,
						Offset:       loc[0],
						Length:       loc[1] - loc[0],
					},
					priority: 92,
				})
				break
			}
		}
	}

	// Detect secrets inside percent-encoded URL segments (mixed-case hex or embedded).
	if strings.ContainsRune(text, '%') {
		for _, loc := range urlEncodedRunRE.FindAllStringIndex(text, -1) {
			seg := text[loc[0]:loc[1]]
			if !strings.ContainsRune(seg, '%') {
				continue
			}
			unescaped, err := url.QueryUnescape(seg)
			if err != nil || unescaped == seg {
				continue
			}
			for _, secret := range s.dotEnvSecrets {
				if strings.Contains(unescaped, secret.Value) {
					out = append(out, rankedFinding{
						finding: Finding{
							RuleID:       "MCP03-DOTENV-LEAK",
							Name:         fmt.Sprintf("DotEnv Secret Leak (%s, url-encoded)", secret.Key),
							Severity:     policy.SeverityCritical,
							MatchPreview: maskSecret(secret.Value),
							SHA256Prefix: secret.SHA256Prefix,
							Offset:       loc[0],
							Length:       loc[1] - loc[0],
						},
						priority: 92,
					})
					break
				}
			}
		}
	}

	return out
}

func findAllLiteral(text, needle string, secret dotEnvSecret, priority int) []rankedFinding {
	if needle == "" {
		return nil
	}
	var out []rankedFinding
	offset := 0
	for {
		idx := strings.Index(text[offset:], needle)
		if idx < 0 {
			break
		}
		start := offset + idx
		out = append(out, rankedFinding{
			finding: Finding{
				RuleID:       "MCP03-DOTENV-LEAK",
				Name:         fmt.Sprintf("DotEnv Secret Leak (%s)", secret.Key),
				Severity:     policy.SeverityCritical,
				MatchPreview: maskSecret(secret.Value),
				SHA256Prefix: secret.SHA256Prefix,
				Offset:       start,
				Length:       len(needle),
			},
			priority: priority,
		})
		offset = start + len(needle)
	}
	return out
}

func tryDecodeBase64(token string) (string, bool) {
	// Quick reject tokens with invalid base64 length (mod 4 == 1 cannot be valid base64).
	trimmed := strings.TrimRight(token, "=")
	if len(trimmed)%4 == 1 {
		return "", false
	}
	hasStdChars := strings.ContainsAny(token, "+/")
	hasURLChars := strings.ContainsAny(token, "-_")
	if hasStdChars && hasURLChars {
		return "", false
	}

	var encodings []*base64.Encoding
	switch {
	case hasURLChars:
		encodings = []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding}
	default:
		encodings = []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding}
	}

	for _, enc := range encodings {
		b, err := enc.DecodeString(token)
		if err == nil && len(b) > 0 {
			return string(b), true
		}
	}
	return "", false
}

// resolveOverlaps merges overlapping spans into disjoint intervals sorted by Offset ascending.
// When multiple rules overlap (including partial overlaps), the merged union span is covered
// completely so Redact never leaks unredacted secret tails, while retaining the highest-priority
// finding's metadata.
func resolveOverlaps(in []rankedFinding) []Finding {
	if len(in) == 0 {
		return nil
	}

	sort.SliceStable(in, func(i, j int) bool {
		if in[i].finding.Offset != in[j].finding.Offset {
			return in[i].finding.Offset < in[j].finding.Offset
		}
		if in[i].priority != in[j].priority {
			return in[i].priority > in[j].priority
		}
		return in[i].finding.Length > in[j].finding.Length
	})

	selected := make([]Finding, 0, len(in))
	cur := in[0]
	curOrigLen := cur.finding.Length

	for i := 1; i < len(in); i++ {
		cand := in[i]
		curStart := cur.finding.Offset
		curEnd := curStart + cur.finding.Length
		candStart := cand.finding.Offset
		candEnd := candStart + cand.finding.Length

		if candStart < curEnd {
			mergedEnd := curEnd
			if candEnd > mergedEnd {
				mergedEnd = candEnd
			}
			if cand.priority > cur.priority || (cand.priority == cur.priority && cand.finding.Length > curOrigLen) {
				cur.priority = cand.priority
				curOrigLen = cand.finding.Length
				cur.finding.RuleID = cand.finding.RuleID
				cur.finding.Name = cand.finding.Name
				cur.finding.Severity = cand.finding.Severity
				cur.finding.MatchPreview = cand.finding.MatchPreview
				cur.finding.SHA256Prefix = cand.finding.SHA256Prefix
			}
			cur.finding.Length = mergedEnd - curStart
			continue
		}

		selected = append(selected, cur.finding)
		cur = cand
		curOrigLen = cand.finding.Length
	}
	selected = append(selected, cur.finding)
	return selected
}

// maskSecret produces a non-reversible preview (e.g. "sk-proj-...XXXX") that never leaks the raw secret.
func maskSecret(raw string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "\r", " "), "\n", " "))
	n := len(clean)
	if n < 12 {
		return "***"
	}
	if n < 16 {
		return clean[:3] + "..." + clean[n-2:]
	}
	prefixLen := 8
	if n < 24 {
		prefixLen = 4
	}
	return clean[:prefixLen] + "..." + clean[n-4:]
}

func builtinRules() []regexRule {
	return []regexRule{
		{
			ruleID:   "MCP03-PEM-PRIVATE-KEY",
			name:     "PEM Private Key",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED) )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:(?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED) )?PRIVATE KEY-----)?`),
			priority: 90,
		},
		{
			ruleID:   "MCP03-AWS-ACCESS-KEY",
			name:     "AWS Access Key ID",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
			priority: 80,
		},
		{
			ruleID:      "MCP03-AWS-SECRET-KEY",
			name:        "AWS Secret Access Key",
			severity:    policy.SeverityCritical,
			re:          regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|aws[-_ ]?secret(?:[-_ ]?access)?[-_ ]?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
			secretGroup: 1,
			priority:    80,
		},
		{
			ruleID:   "MCP03-GITHUB-TOKEN",
			name:     "GitHub Personal/App Token",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`),
			priority: 80,
		},
		{
			ruleID:   "MCP03-ANTHROPIC-KEY",
			name:     "Anthropic API Key",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,200}\b`),
			priority: 85,
		},
		{
			ruleID:   "MCP03-OPENAI-KEY",
			name:     "OpenAI API Key",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}\b`),
			validate: func(match string) bool {
				return !strings.HasPrefix(match, "sk-ant-")
			},
			priority: 75,
		},
		{
			ruleID:   "MCP03-GOOGLE-API-KEY",
			name:     "Google / Gemini API Key",
			severity: policy.SeverityHigh,
			re:       regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
			priority: 75,
		},
		{
			ruleID:   "MCP03-SLACK-TOKEN",
			name:     "Slack Token",
			severity: policy.SeverityHigh,
			re:       regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,200}\b`),
			priority: 75,
		},
		{
			ruleID:   "MCP03-STRIPE-KEY",
			name:     "Stripe Live API Key",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{20,200}\b`),
			priority: 80,
		},
		{
			ruleID:   "MCP03-HUGGINGFACE-TOKEN",
			name:     "HuggingFace Access Token",
			severity: policy.SeverityHigh,
			re:       regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,100}\b`),
			priority: 75,
		},
		{
			ruleID:   "MCP03-JWT",
			name:     "JSON Web Token (JWT)",
			severity: policy.SeverityHigh,
			re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
			priority: 70,
		},
		{
			ruleID:   "MCP03-DB-CONNSTRING",
			name:     "Database Connection String with Credentials",
			severity: policy.SeverityCritical,
			re:       regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver)://[^:\s/@"']*:[^@\s"']{3,}@[^\s"'<>]+`),
			validate: func(match string) bool {
				// Avoid false positives on already redacted strings or masked passwords.
				if strings.Contains(match, "[MCPGATE-REDACTED:") {
					return false
				}
				schemeEnd := strings.Index(match, "://")
				if schemeEnd < 0 {
					return false
				}
				rest := match[schemeEnd+3:]
				atIdx := strings.IndexByte(rest, '@')
				if atIdx < 0 {
					return false
				}
				userInfo := rest[:atIdx]
				colonIdx := strings.IndexByte(userInfo, ':')
				if colonIdx < 0 {
					return false
				}
				pass := userInfo[colonIdx+1:]
				return pass != "" && strings.Trim(pass, "*") != ""
			},
			priority: 80,
		},
	}
}
