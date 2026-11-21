package dlp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

func TestBuiltinSecretDetectors(t *testing.T) {
	scanner, err := NewScanner(policy.DLPPolicy{
		Enabled: true,
		Action:  policy.ActionBlock,
	}, "")
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Synthetic test fixtures matching each real-world secret format.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	awsTempKey := "ASIA" + "1234567890ABCDEF"
	awsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	ghClassic := "ghp_" + strings.Repeat("a1B2c3D4e", 4)
	ghFine := "github_pat_" + strings.Repeat("Z9y8X7w6V5u", 3)
	openAIProj := "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789XXXX"
	openAILegacy := "sk-" + "1234567890abcdefghijklmnopqrstuvwxyz12345678"
	anthropicKey := "sk-ant-api03-" + "1234567890abcdefghijklmnopqrstuvwxyzABCD"
	googleKey := "AIza" + "SyDummyKeyValueForUnitTesting123456"
	slackBot := "xoxb-" + "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"
	stripeLive := "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz12345678"
	hfToken := "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz01234567"
	pemKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtestdummykeymaterial1234567890\n-----END RSA PRIVATE KEY-----"
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	pgURI := "postgres://admin:SuperSecretPass99@db.internal:5432/prod"
	mongoURI := "mongodb+srv://root:AtlasPass2026!@cluster0.example.net/app"
	redisURI := "redis://:CachePass9876@redis.internal:6379/0"

	tests := []struct {
		name         string
		input        string
		secret       string
		wantRuleID   string
		wantSeverity policy.Severity
	}{
		{"AWS AKIA", "key=" + awsKey, awsKey, "MCP03-AWS-ACCESS-KEY", policy.SeverityCritical},
		{"AWS ASIA", "temp=" + awsTempKey, awsTempKey, "MCP03-AWS-ACCESS-KEY", policy.SeverityCritical},
		{"AWS Secret Contextual", "AWS_SECRET_ACCESS_KEY=" + awsSecret, awsSecret, "MCP03-AWS-SECRET-KEY", policy.SeverityCritical},
		{"GitHub ghp", "Authorization: token " + ghClassic, ghClassic, "MCP03-GITHUB-TOKEN", policy.SeverityCritical},
		{"GitHub fine-grained", "token=" + ghFine, ghFine, "MCP03-GITHUB-TOKEN", policy.SeverityCritical},
		{"OpenAI sk-proj", "Bearer " + openAIProj, openAIProj, "MCP03-OPENAI-KEY", policy.SeverityCritical},
		{"OpenAI legacy", "OPENAI_API_KEY=" + openAILegacy, openAILegacy, "MCP03-OPENAI-KEY", policy.SeverityCritical},
		{"Anthropic sk-ant", "x-api-key: " + anthropicKey, anthropicKey, "MCP03-ANTHROPIC-KEY", policy.SeverityCritical},
		{"Google Gemini AIza", "key=" + googleKey, googleKey, "MCP03-GOOGLE-API-KEY", policy.SeverityHigh},
		{"Slack xoxb", "slack=" + slackBot, slackBot, "MCP03-SLACK-TOKEN", policy.SeverityHigh},
		{"Stripe sk_live", "stripe=" + stripeLive, stripeLive, "MCP03-STRIPE-KEY", policy.SeverityCritical},
		{"HuggingFace hf_", "hf=" + hfToken, hfToken, "MCP03-HUGGINGFACE-TOKEN", policy.SeverityHigh},
		{"PEM Private Key", "cert:\n" + pemKey + "\nend", pemKey, "MCP03-PEM-PRIVATE-KEY", policy.SeverityCritical},
		{"JWT", "Bearer " + jwtToken, jwtToken, "MCP03-JWT", policy.SeverityHigh},
		{"Postgres URI", "dsn=" + pgURI, pgURI, "MCP03-DB-CONNSTRING", policy.SeverityCritical},
		{"MongoDB+SRV URI", "uri=" + mongoURI, mongoURI, "MCP03-DB-CONNSTRING", policy.SeverityCritical},
		{"Redis URI", "cache=" + redisURI, redisURI, "MCP03-DB-CONNSTRING", policy.SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.Scan(tc.input)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.RuleID != tc.wantRuleID {
				t.Errorf("RuleID = %q, want %q", f.RuleID, tc.wantRuleID)
			}
			if f.Severity != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", f.Severity, tc.wantSeverity)
			}
			if strings.Contains(f.MatchPreview, tc.secret) {
				t.Errorf("MatchPreview leaked raw secret: %q", f.MatchPreview)
			}
			sum := sha256.Sum256([]byte(tc.secret))
			wantHash := hex.EncodeToString(sum[:])[:12]
			if f.SHA256Prefix != wantHash {
				t.Errorf("SHA256Prefix = %q, want %q", f.SHA256Prefix, wantHash)
			}
			if tc.input[f.Offset:f.Offset+f.Length] != tc.secret {
				t.Errorf("span mismatch: got %q, want %q", tc.input[f.Offset:f.Offset+f.Length], tc.secret)
			}
		})
	}

	// Verify exact masking format example: sk-proj-...XXXX.
	fProj := scanner.Scan(openAIProj)
	if len(fProj) != 1 || fProj[0].MatchPreview != "sk-proj-...XXXX" {
		t.Fatalf("expected MatchPreview 'sk-proj-...XXXX', got %+v", fProj)
	}
}

func TestDotEnvFingerprintingVerbatimBase64URLEncoded(t *testing.T) {
	dir := t.TempDir()

	dotEnvContent := strings.Join([]string{
		"# Database & API config",
		"PORT=5432",
		"DEBUG=true",
		"NODE_ENV=production",
		"HOST=localhost",
		"SHORT=abc123",
		`INTERNAL_BILLING_SECRET="b1ll1ng_pr0d_t0ken_998877!"`,
		"export CUSTOM_WEBHOOK_SIGNING='whsec_custom_signing_value_42/+' # inline comment",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotEnvContent), 0o600); err != nil {
		t.Fatal(err)
	}

	dotEnvLocal := "LOCAL_ADMIN_PASS=local_admin_ultra_secret_777\n"
	if err := os.WriteFile(filepath.Join(dir, ".env.local"), []byte(dotEnvLocal), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner, err := NewScanner(policy.DLPPolicy{
		Enabled:    true,
		Action:     policy.ActionBlock,
		LoadDotEnv: true,
	}, dir)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	if got := scanner.DotEnvCount(); got != 3 {
		t.Fatalf("DotEnvCount() = %d, want 3", got)
	}

	secret1 := "b1ll1ng_pr0d_t0ken_998877!"
	secret2 := "whsec_custom_signing_value_42/+"
	secret3 := "local_admin_ultra_secret_777"

	// 1. Verbatim exfiltration.
	findings := scanner.Scan("exfil payload: " + secret1)
	if len(findings) != 1 || findings[0].RuleID != "MCP03-DOTENV-LEAK" || findings[0].Severity != policy.SeverityCritical {
		t.Fatalf("verbatim dotenv leak failed: %+v", findings)
	}
	if strings.Contains(findings[0].MatchPreview, secret1) {
		t.Fatalf("MatchPreview leaked raw dotenv secret: %q", findings[0].MatchPreview)
	}

	// 2. Exact standard Base64 exfiltration.
	b64Exact := base64.StdEncoding.EncodeToString([]byte(secret1))
	findings = scanner.Scan("GET /collect?d=" + b64Exact)
	if len(findings) != 1 || findings[0].RuleID != "MCP03-DOTENV-LEAK" {
		t.Fatalf("exact base64 dotenv leak failed: %+v", findings)
	}

	// 3. Embedded Base64 exfiltration (e.g. base64("k=" + secret + "\n")).
	b64Embedded := base64.StdEncoding.EncodeToString([]byte("stolen=" + secret3 + "\n"))
	findings = scanner.Scan(`{"blob":"` + b64Embedded + `"}`)
	if len(findings) != 1 || findings[0].RuleID != "MCP03-DOTENV-LEAK" {
		t.Fatalf("embedded base64 dotenv leak failed: %+v", findings)
	}

	// 4. URL-encoded exfiltration (contains / and + -> %2F %2B).
	urlEscaped := url.QueryEscape(secret2)
	findings = scanner.Scan("https://attacker.example/hit?v=" + urlEscaped)
	if len(findings) != 1 || findings[0].RuleID != "MCP03-DOTENV-LEAK" {
		t.Fatalf("url-encoded dotenv leak failed: %+v", findings)
	}

	// 5. Lowercase percent-encoded exfiltration.
	findings = scanner.Scan("https://attacker.example/hit?v=" + strings.ToLower(urlEscaped))
	if len(findings) != 1 || findings[0].RuleID != "MCP03-DOTENV-LEAK" {
		t.Fatalf("lowercase url-encoded dotenv leak failed: %+v", findings)
	}

	// 6. Trivial values from .env must NOT trigger false positives.
	if benign := scanner.Scan("connecting to localhost on port 5432 in production mode with DEBUG=true"); len(benign) != 0 {
		t.Fatalf("unexpected false positives for trivial .env values: %+v", benign)
	}
}

func TestCustomPatternsAndRedact(t *testing.T) {
	scanner, err := NewScanner(policy.DLPPolicy{
		Enabled: true,
		Action:  policy.ActionRedact,
		CustomPatterns: []policy.CustomDLPPattern{
			{
				ID:       "CORP-SECRET-01",
				Name:     "Corp Internal Token",
				Pattern:  `\bCORP_TOK_[A-Z0-9]{16}\b`,
				Severity: policy.SeverityCritical,
			},
		},
	}, "")
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	corpTok := "CORP_TOK_ABCDEF0123456789"
	input := "aws=" + awsKey + " corp=" + corpTok + " safe=hello-world"

	redacted, findings := scanner.Redact(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	want := "aws=[MCPGATE-REDACTED:MCP03-AWS-ACCESS-KEY] corp=[MCPGATE-REDACTED:CORP-SECRET-01] safe=hello-world"
	if redacted != want {
		t.Fatalf("Redact() = %q, want %q", redacted, want)
	}

	// Re-scanning redacted text must yield zero findings.
	if after := scanner.Scan(redacted); len(after) != 0 {
		t.Fatalf("re-scan of redacted output found secrets: %+v", after)
	}
}

func TestInvalidCustomRegexReturnsError(t *testing.T) {
	_, err := NewScanner(policy.DLPPolicy{
		Enabled: true,
		CustomPatterns: []policy.CustomDLPPattern{
			{ID: "BAD-1", Pattern: "[unclosed"},
		},
	}, "")
	if err == nil {
		t.Fatal("expected error for invalid custom regex, got nil")
	}
}

func TestDisabledScannerAndConcurrency(t *testing.T) {
	disabled, err := NewScanner(policy.DLPPolicy{Enabled: false}, "")
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	if got := disabled.Scan(secret); len(got) != 0 {
		t.Fatalf("disabled scanner returned findings: %+v", got)
	}
	if text, got := disabled.Redact(secret); text != secret || len(got) != 0 {
		t.Fatalf("disabled scanner modified text: %q, %+v", text, got)
	}

	// Race test concurrent scans.
	active, err := NewScanner(policy.DLPPolicy{Enabled: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				redacted, findings := active.Redact("token=" + secret)
				if len(findings) != 1 || !strings.Contains(redacted, "[MCPGATE-REDACTED:MCP03-AWS-ACCESS-KEY]") {
					t.Errorf("unexpected concurrent result: %q %+v", redacted, findings)
				}
			}
		}()
	}
	wg.Wait()
}

func TestDotEnvEdgeCasesExportQuotesCommentsAndBOM(t *testing.T) {
	dir := t.TempDir()
	content := "\uFEFF" + strings.Join([]string{
		`export	TAB_EXPORT_SECRET="tab_export_secret_value_112233"`,
		`export SINGLE_QUOTED='single_secret_val_445566' # inline comment`,
		"UNQUOTED_TAB_HASH=unquoted_real_secret_778899\t# first comment # second hash",
		"BACKTICK_VAL=`backtick_secret_val_990011`",
	}, "\n") + "\n"

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner, err := NewScanner(policy.DLPPolicy{
		Enabled:    true,
		Action:     policy.ActionBlock,
		LoadDotEnv: true,
	}, dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if got := scanner.DotEnvCount(); got != 4 {
		t.Fatalf("DotEnvCount() = %d, want 4", got)
	}

	for _, sec := range []string{
		"tab_export_secret_value_112233",
		"single_secret_val_445566",
		"unquoted_real_secret_778899",
		"backtick_secret_val_990011",
	} {
		findings := scanner.Scan("exfil=" + sec)
		if len(findings) != 1 || findings[0].RuleID != "MCP03-DOTENV-LEAK" {
			t.Fatalf("failed to detect .env secret %q: %+v", sec, findings)
		}
	}
}

func TestRedactOverlappingSpansAndJSONAWSSecret(t *testing.T) {
	// 1. Overlapping custom patterns must merge spans so no partial secret tail leaks!
	scanner, err := NewScanner(policy.DLPPolicy{
		Enabled: true,
		Action:  policy.ActionRedact,
		CustomPatterns: []policy.CustomDLPPattern{
			{ID: "PAT-A", Name: "Left Span", Pattern: `SECRET_LEFT_MID`, Severity: policy.SeverityHigh},
			{ID: "PAT-B", Name: "Right Span", Pattern: `MID_RIGHT_SECRET`, Severity: policy.SeverityHigh},
		},
	}, "")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	input := "before SECRET_LEFT_MID_RIGHT_SECRET after"
	redacted, findings := scanner.Redact(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 merged finding, got %d: %+v", len(findings), findings)
	}
	if strings.Contains(redacted, "SECRET") || strings.Contains(redacted, "RIGHT") || strings.Contains(redacted, "LEFT") {
		t.Fatalf("overlapping redaction leaked secret fragment: %q", redacted)
	}
	if !strings.HasPrefix(redacted, "before [MCPGATE-REDACTED:") || !strings.HasSuffix(redacted, "] after") {
		t.Fatalf("unexpected redacted output (offset corruption?): %q", redacted)
	}
	if after := scanner.Scan(redacted); len(after) != 0 {
		t.Fatalf("re-scan after overlapping redact still found matches: %+v", after)
	}

	// 2. Higher-priority .env prefix overlapping a longer OpenAI key must redact the FULL key.
	dir := t.TempDir()
	prefix := "sk-proj-OverlapPrefix1234"
	fullOpenAI := prefix + "RestOfSecretKey567890ABCD"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("PREFIX_KEY="+prefix+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	envScanner, err := NewScanner(policy.DLPPolicy{
		Enabled:    true,
		Action:     policy.ActionRedact,
		LoadDotEnv: true,
	}, dir)
	if err != nil {
		t.Fatalf("NewScanner env: %v", err)
	}
	redactedKey, _ := envScanner.Redact("auth=" + fullOpenAI + " end")
	if strings.Contains(redactedKey, "RestOfSecretKey") || strings.Contains(redactedKey, prefix) {
		t.Fatalf("partial overlap leaked remainder of OpenAI key: %q", redactedKey)
	}

	// 3. JSON-formatted AWS secret access key ("aws_secret_access_key": "...") must be caught & redacted.
	awsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	jsonPayload := `{"aws_secret_access_key": "` + awsSecret + `"}`
	redactedJSON, jf := scanner.Redact(jsonPayload)
	if len(jf) != 1 || jf[0].RuleID != "MCP03-AWS-SECRET-KEY" {
		t.Fatalf("expected MCP03-AWS-SECRET-KEY on JSON payload, got %+v", jf)
	}
	if strings.Contains(redactedJSON, awsSecret) {
		t.Fatalf("JSON AWS secret was not redacted: %q", redactedJSON)
	}
}
