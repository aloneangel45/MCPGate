package dlp

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// minDotEnvSecretLen is the minimum character length for a .env value to be fingerprinted.
const minDotEnvSecretLen = 8

// dotEnvSecret stores a single fingerprinted secret loaded from a .env file.
type dotEnvSecret struct {
	Key          string
	Value        string
	SHA256Prefix string
	Variants     []string // precomputed encoded representations (base64, url-encoded)
}

var trivialDotEnvValues = map[string]struct{}{
	"true":        {},
	"false":       {},
	"yes":         {},
	"no":          {},
	"on":          {},
	"off":         {},
	"null":        {},
	"none":        {},
	"undefined":   {},
	"localhost":   {},
	"127.0.0.1":   {},
	"0.0.0.0":     {},
	"development": {},
	"production":  {},
	"staging":     {},
	"testing":     {},
	"changeme":    {},
	"placeholder": {},
}

// loadDotEnvSecrets reads .env files and builds exact + encoded fingerprints in memory.
func loadDotEnvSecrets(paths []string, workDir string) []dotEnvSecret {
	candidates := paths
	if len(candidates) == 0 {
		candidates = []string{".env", ".env.local"}
	}

	seenValues := make(map[string]struct{})
	var secrets []dotEnvSecret

	for _, rawPath := range candidates {
		p := strings.TrimSpace(rawPath)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) && workDir != "" {
			p = filepath.Join(workDir, p)
		}
		entries, err := parseDotEnvFile(p)
		if err != nil {
			// Missing or unreadable .env files are skipped gracefully.
			continue
		}
		for _, entry := range entries {
			if _, exists := seenValues[entry.Value]; exists {
				continue
			}
			seenValues[entry.Value] = struct{}{}
			secrets = append(secrets, entry)
		}
	}

	return secrets
}

func parseDotEnvFile(filePath string) ([]dotEnvSecret, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []dotEnvSecret
	scanner := bufio.NewScanner(f)
	// Support large .env values such as PEM blocks or long tokens.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimPrefix(scanner.Text(), "\uFEFF")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t") {
			line = strings.TrimSpace(line[len("export"):])
		}
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eqIdx])
		rawVal := strings.TrimSpace(line[eqIdx+1:])
		if key == "" || rawVal == "" {
			continue
		}
		val := unquoteDotEnvValue(rawVal)
		if isTrivialDotEnvValue(val) {
			continue
		}

		results = append(results, dotEnvSecret{
			Key:          key,
			Value:        val,
			SHA256Prefix: sha256HexPrefix(val),
			Variants:     buildEncodedVariants(val),
		})
	}

	return results, scanner.Err()
}

func unquoteDotEnvValue(raw string) string {
	if len(raw) >= 2 {
		if raw[0] == '"' {
			// Double-quoted value: find closing unescaped quote.
			var b strings.Builder
			escaped := false
			for i := 1; i < len(raw); i++ {
				ch := raw[i]
				if escaped {
					switch ch {
					case 'n':
						b.WriteByte('\n')
					case 'r':
						b.WriteByte('\r')
					case 't':
						b.WriteByte('\t')
					default:
						b.WriteByte(ch)
					}
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if ch == '"' {
					return b.String()
				}
				b.WriteByte(ch)
			}
			return strings.Trim(raw, `"`)
		}
		if raw[0] == '\'' {
			if end := strings.IndexByte(raw[1:], '\''); end >= 0 {
				return raw[1 : end+1]
			}
			return strings.Trim(raw, `'`)
		}
		if raw[0] == '`' {
			if end := strings.IndexByte(raw[1:], '`'); end >= 0 {
				return raw[1 : end+1]
			}
			return strings.Trim(raw, "`")
		}
	}

	// Unquoted value: strip the earliest inline comment preceded by space or tab.
	for i := 1; i < len(raw); i++ {
		if raw[i] == '#' && (raw[i-1] == ' ' || raw[i-1] == '\t') {
			raw = raw[:i]
			break
		}
	}
	return strings.TrimSpace(raw)
}

func isTrivialDotEnvValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	if len(trimmed) < minDotEnvSecretLen {
		return true
	}
	lower := strings.ToLower(trimmed)
	if _, trivial := trivialDotEnvValues[lower]; trivial {
		return true
	}
	// Ignore pure numeric values (ports, timeouts, IDs).
	if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return true
	}
	return false
}

func buildEncodedVariants(val string) []string {
	seen := map[string]struct{}{val: {}}
	var out []string
	add := func(s string) {
		if len(s) < minDotEnvSecretLen {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	rawBytes := []byte(val)
	add(base64.StdEncoding.EncodeToString(rawBytes))
	add(base64.RawStdEncoding.EncodeToString(rawBytes))
	add(base64.URLEncoding.EncodeToString(rawBytes))
	add(base64.RawURLEncoding.EncodeToString(rawBytes))

	qe := url.QueryEscape(val)
	add(qe)
	add(strings.ToLower(qe))

	pe := url.PathEscape(val)
	add(pe)
	add(strings.ToLower(pe))

	return out
}

func sha256HexPrefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
