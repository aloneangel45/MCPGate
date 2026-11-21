package egress

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aloneangel45/mcpgate/pkg/dlp"
	"github.com/aloneangel45/mcpgate/pkg/policy"
)

func TestValidateTargetIPAndHost(t *testing.T) {
	cfg := policy.NetworkPolicy{
		Enabled:            true,
		BlockPrivateIPs:    true,
		BlockCloudMetadata: true,
	}

	ipCases := []struct {
		ip          string
		wantBlocked bool
		wantRuleID  string
	}{
		// Cloud metadata endpoints
		{"169.254.169.254", true, "MCP04-SSRF-METADATA"},
		{"169.254.170.2", true, "MCP04-SSRF-METADATA"},
		{"100.100.100.200", true, "MCP04-SSRF-METADATA"},
		{"fd00:ec2::254", true, "MCP04-SSRF-METADATA"},
		{"::ffff:169.254.169.254", true, "MCP04-SSRF-METADATA"},

		// Loopback, private, link-local, CGNAT, ULA, unspecified
		{"127.0.0.1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"127.0.1.5", true, "MCP04-SSRF-PRIVATE-IP"},
		{"::1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"10.0.0.1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"172.16.0.1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"172.31.255.254", true, "MCP04-SSRF-PRIVATE-IP"},
		{"192.168.1.1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"169.254.1.2", true, "MCP04-SSRF-PRIVATE-IP"},
		{"fe80::1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"100.64.0.1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"fc00::1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"fd12:3456:789a::1", true, "MCP04-SSRF-PRIVATE-IP"},
		{"0.0.0.0", true, "MCP04-SSRF-PRIVATE-IP"},
		{"::", true, "MCP04-SSRF-PRIVATE-IP"},
		{"::ffff:10.0.0.1", true, "MCP04-SSRF-PRIVATE-IP"},

		// Public routable IPs
		{"1.1.1.1", false, ""},
		{"8.8.8.8", false, ""},
		{"93.184.216.34", false, ""},
		{"2606:4700:4700::1111", false, ""},
	}

	for _, tc := range ipCases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse test IP %q", tc.ip)
		}
		blocked, ruleID, _ := ValidateTargetIP(ip, cfg)
		if blocked != tc.wantBlocked || ruleID != tc.wantRuleID {
			t.Errorf("ValidateTargetIP(%s) = (%v, %q), want (%v, %q)", tc.ip, blocked, ruleID, tc.wantBlocked, tc.wantRuleID)
		}
	}

	hostCases := []struct {
		host        string
		wantBlocked bool
		wantRuleID  string
	}{
		{"metadata.google.internal", true, "MCP04-SSRF-METADATA"},
		{"METADATA.GOOGLE.INTERNAL.", true, "MCP04-SSRF-METADATA"},
		{"metadata.goog", true, "MCP04-SSRF-METADATA"},
		{"instance-data", true, "MCP04-SSRF-METADATA"},
		{"sub.metadata.google.internal", true, "MCP04-SSRF-METADATA"},
		{"api.github.com", false, ""},
	}

	for _, tc := range hostCases {
		blocked, ruleID, _ := ValidateTargetHost(tc.host, cfg)
		if blocked != tc.wantBlocked || ruleID != tc.wantRuleID {
			t.Errorf("ValidateTargetHost(%q) = (%v, %q), want (%v, %q)", tc.host, blocked, ruleID, tc.wantBlocked, tc.wantRuleID)
		}
	}
}

func TestProxySSRFAndDomainPolicyBlocks(t *testing.T) {
	var mu sync.Mutex
	var events []policy.SecurityEvent
	recordEvent := func(ev policy.SecurityEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}

	t.Run("SSRF metadata and private IP blocking", func(t *testing.T) {
		pol, _ := policy.Preset("balanced")
		pol.Network.AllowPorts = nil // allow any port so SSRF check is reached
		proxy, err := New(Options{
			Policy:  pol,
			OnEvent: recordEvent,
		})
		if err != nil {
			t.Fatalf("New proxy failed: %v", err)
		}
		defer proxy.Close()

		client := newProxyHTTPClient(t, proxy.ProxyURL(), nil)

		targets := []struct {
			url        string
			wantRuleID string
		}{
			{"http://169.254.169.254/latest/meta-data/", "MCP04-SSRF-METADATA"},
			{"http://metadata.google.internal/computeMetadata/v1/", "MCP04-SSRF-METADATA"},
			{"http://10.0.0.1/admin", "MCP04-SSRF-PRIVATE-IP"},
			{"http://127.0.0.1:8080/internal", "MCP04-SSRF-PRIVATE-IP"},
		}

		for _, tc := range targets {
			resp, err := client.Get(tc.url)
			if err != nil {
				t.Fatalf("request to %s failed unexpectedly: %v", tc.url, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403; body=%s", tc.url, resp.StatusCode, string(body))
			}
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("%s: invalid JSON body %q: %v", tc.url, string(body), err)
			}
			if payload["rule_id"] != tc.wantRuleID {
				t.Errorf("%s: rule_id = %v, want %q", tc.url, payload["rule_id"], tc.wantRuleID)
			}
		}
	})

	t.Run("Domain allowlist, denylist, port restriction, and airgapped", func(t *testing.T) {
		// Airgapped preset.
		airPol, _ := policy.Preset("airgapped")
		airProxy, err := New(Options{Policy: airPol})
		if err != nil {
			t.Fatal(err)
		}
		defer airProxy.Close()

		airClient := newProxyHTTPClient(t, airProxy.ProxyURL(), nil)
		resp, err := airClient.Get("http://example.com/")
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP06-EGRESS-AIRGAPPED")

		// Allowlist + denylist + port restriction.
		strictPol := &policy.Policy{
			Version: policy.CurrentVersion,
			Network: policy.NetworkPolicy{
				Enabled:            true,
				AllowDomains:       []string{"*.allowed.example"},
				DenyDomains:        []string{"blocked.allowed.example"},
				AllowPorts:         []int{80, 443},
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
		}
		strictProxy, err := New(Options{Policy: strictPol})
		if err != nil {
			t.Fatal(err)
		}
		defer strictProxy.Close()

		strictClient := newProxyHTTPClient(t, strictProxy.ProxyURL(), nil)

		resp, err = strictClient.Get("http://evil.example/")
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP06-EGRESS-NOT-ALLOWLISTED")

		resp, err = strictClient.Get("http://blocked.allowed.example/")
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP06-EGRESS-DENY")

		resp, err = strictClient.Get("http://api.allowed.example:8443/")
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP06-EGRESS-PORT-DENY")
	})

	mu.Lock()
	if len(events) < 4 {
		t.Errorf("expected at least 4 SSRF security events, got %d", len(events))
	}
	mu.Unlock()
}

func TestHTTPProxyDLPBlockRedactAndAllow(t *testing.T) {
	// Prepare a .env file for live fingerprinting.
	workDir := t.TempDir()
	dotEnvSecret := "vault_prod_master_secret_987654"
	if err := os.WriteFile(filepath.Join(workDir, ".env"), []byte("VAULT_TOKEN="+dotEnvSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var upstreamHits atomic.Int32
	var lastBody atomic.Value
	var lastAuthHeader atomic.Value
	var lastQuery atomic.Value

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		lastAuthHeader.Store(r.Header.Get("X-Secret-Header"))
		lastQuery.Store(r.URL.RawQuery)
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("received:" + string(b)))
	}))
	defer upstream.Close()

	upstreamPort := mustURLPort(t, upstream.URL)

	openAIKey := "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789XXXX"
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	ghToken := "ghp_" + strings.Repeat("a1B2c3D4e", 4)

	t.Run("DLP block mode blocks body, header, and base64 dotenv query leak", func(t *testing.T) {
		upstreamHits.Store(0)
		var evMu sync.Mutex
		var dlpEvents []policy.SecurityEvent

		pol := &policy.Policy{
			Version: policy.CurrentVersion,
			Network: policy.NetworkPolicy{
				Enabled:            true,
				AllowPorts:         []int{upstreamPort},
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
			DLP: policy.DLPPolicy{
				Enabled:    true,
				Action:     policy.ActionBlock,
				LoadDotEnv: true,
			},
		}
		scanner, err := dlp.NewScanner(pol.DLP, workDir)
		if err != nil {
			t.Fatal(err)
		}

		proxy, err := New(Options{
			Policy:               pol,
			Scanner:              scanner,
			AllowLoopbackForTest: true,
			OnEvent: func(ev policy.SecurityEvent) {
				evMu.Lock()
				dlpEvents = append(dlpEvents, ev)
				evMu.Unlock()
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()

		client := newProxyHTTPClient(t, proxy.ProxyURL(), nil)

		// 1. Benign request passes through.
		resp, err := client.Post(upstream.URL+"/ok", "text/plain", strings.NewReader("hello clean world"))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "received:hello clean world" {
			t.Fatalf("clean request failed: status=%d body=%q", resp.StatusCode, string(body))
		}
		if upstreamHits.Load() != 1 {
			t.Fatalf("expected 1 upstream hit, got %d", upstreamHits.Load())
		}

		// 2. Body containing OpenAI key -> 403 Forbidden.
		resp, err = client.Post(upstream.URL+"/exfil", "application/json", strings.NewReader(`{"key":"`+openAIKey+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP03-OPENAI-KEY")

		// 3. Header containing GitHub token -> 403 Forbidden.
		req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/hdr", nil)
		req.Header.Set("Authorization", "Bearer "+ghToken)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP03-GITHUB-TOKEN")

		// 4. URL query exfiltrating base64-encoded .env secret -> 403 Forbidden.
		b64Secret := base64.StdEncoding.EncodeToString([]byte(dotEnvSecret))
		resp, err = client.Get(upstream.URL + "/collect?d=" + url.QueryEscape(b64Secret))
		if err != nil {
			t.Fatal(err)
		}
		assertForbiddenRule(t, resp, "MCP03-DOTENV-LEAK")

		// Upstream must NEVER have received any of the 3 blocked requests.
		if upstreamHits.Load() != 1 {
			t.Fatalf("blocked requests leaked to upstream! hits=%d, want 1", upstreamHits.Load())
		}

		evMu.Lock()
		if len(dlpEvents) != 3 {
			t.Fatalf("expected 3 DLP events, got %d: %+v", len(dlpEvents), dlpEvents)
		}
		for _, ev := range dlpEvents {
			if ev.Category != "dlp" || ev.Action != "blocked" {
				t.Errorf("unexpected DLP event: %+v", ev)
			}
		}
		evMu.Unlock()
	})

	t.Run("DLP redact mode scrubs body, headers, and query before forwarding", func(t *testing.T) {
		upstreamHits.Store(0)
		var evMu sync.Mutex
		var events []policy.SecurityEvent

		pol := &policy.Policy{
			Version: policy.CurrentVersion,
			Network: policy.NetworkPolicy{
				Enabled:            true,
				AllowPorts:         []int{upstreamPort},
				BlockPrivateIPs:    true,
				BlockCloudMetadata: true,
			},
			DLP: policy.DLPPolicy{
				Enabled:    true,
				Action:     policy.ActionRedact,
				LoadDotEnv: true,
			},
		}
		scanner, err := dlp.NewScanner(pol.DLP, workDir)
		if err != nil {
			t.Fatal(err)
		}

		proxy, err := New(Options{
			Policy:               pol,
			Scanner:              scanner,
			AllowLoopbackForTest: true,
			OnEvent: func(ev policy.SecurityEvent) {
				evMu.Lock()
				events = append(events, ev)
				evMu.Unlock()
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()

		client := newProxyHTTPClient(t, proxy.ProxyURL(), nil)
		req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/send?k="+openAIKey, strings.NewReader("aws="+awsKey))
		req.Header.Set("X-Secret-Header", ghToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("redacted request status = %d, want 200; body=%s", resp.StatusCode, string(respBody))
		}
		if upstreamHits.Load() != 1 {
			t.Fatalf("expected 1 upstream hit, got %d", upstreamHits.Load())
		}

		gotBody := lastBody.Load().(string)
		if strings.Contains(gotBody, awsKey) || !strings.Contains(gotBody, "[MCPGATE-REDACTED:MCP03-AWS-ACCESS-KEY]") {
			t.Errorf("upstream body not properly redacted: %q", gotBody)
		}
		gotHdr := lastAuthHeader.Load().(string)
		if strings.Contains(gotHdr, ghToken) || !strings.Contains(gotHdr, "[MCPGATE-REDACTED:MCP03-GITHUB-TOKEN]") {
			t.Errorf("upstream header not properly redacted: %q", gotHdr)
		}
		gotQuery := lastQuery.Load().(string)
		if strings.Contains(gotQuery, openAIKey) || !strings.Contains(gotQuery, "[MCPGATE-REDACTED:MCP03-OPENAI-KEY]") {
			t.Errorf("upstream query not properly redacted: %q", gotQuery)
		}

		evMu.Lock()
		if len(events) != 1 || events[0].Action != "redacted" || events[0].Category != "dlp" {
			t.Errorf("expected 1 redacted DLP event, got %+v", events)
		}
		evMu.Unlock()
	})
}

func TestHTTPSConnectTunnelWithoutTLSInspection(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls-tunnel-ok"))
	}))
	defer upstream.Close()

	upstreamPort := mustURLPort(t, upstream.URL)

	pol := &policy.Policy{
		Version: policy.CurrentVersion,
		Network: policy.NetworkPolicy{
			Enabled:            true,
			AllowPorts:         []int{upstreamPort},
			BlockPrivateIPs:    true,
			BlockCloudMetadata: true,
			InspectTLS:         false,
		},
	}

	proxy, err := New(Options{
		Policy:               pol,
		AllowLoopbackForTest: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// Verify EnvVars without InspectTLS.
	envStr := strings.Join(proxy.EnvVars(), "\n")
	for _, want := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy=", "NO_PROXY="} {
		if !strings.Contains(envStr, want) {
			t.Errorf("EnvVars() missing %q:\n%s", want, envStr)
		}
	}
	if strings.Contains(envStr, "SSL_CERT_FILE=") {
		t.Errorf("EnvVars() should not contain SSL_CERT_FILE when InspectTLS=false")
	}

	// Client trusts upstream's test cert directly (proving raw passthrough with zero MITM).
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	client := newProxyHTTPClient(t, proxy.ProxyURL(), pool)

	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("HTTPS CONNECT tunnel request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "tls-tunnel-ok" {
		t.Fatalf("unexpected tunnel response: status=%d body=%q", resp.StatusCode, string(body))
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || !resp.TLS.PeerCertificates[0].Equal(upstream.Certificate()) {
		t.Errorf("expected original upstream peer cert in non-MITM CONNECT tunnel")
	}
}

func TestHTTPSConnectInspectTLSEphemeralCAMITMDLPBlock(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mitm-upstream-ok:" + string(b)))
	}))
	defer upstream.Close()

	upstreamPort := mustURLPort(t, upstream.URL)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	pol := &policy.Policy{
		Version: policy.CurrentVersion,
		Network: policy.NetworkPolicy{
			Enabled:            true,
			AllowPorts:         []int{upstreamPort},
			BlockPrivateIPs:    true,
			BlockCloudMetadata: true,
			InspectTLS:         true,
		},
		DLP: policy.DLPPolicy{
			Enabled: true,
			Action:  policy.ActionBlock,
		},
	}
	scanner, err := dlp.NewScanner(pol.DLP, "")
	if err != nil {
		t.Fatal(err)
	}

	var evMu sync.Mutex
	var events []policy.SecurityEvent

	proxy, err := New(Options{
		Policy:               pol,
		Scanner:              scanner,
		UpstreamRootCAs:      upstreamRoots,
		AllowLoopbackForTest: true,
		OnEvent: func(ev policy.SecurityEvent) {
			evMu.Lock()
			events = append(events, ev)
			evMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("New proxy with InspectTLS failed: %v", err)
	}

	caPath := proxy.CACertPath()
	if caPath == "" {
		t.Fatal("expected non-empty CACertPath when InspectTLS=true")
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Fatalf("ephemeral CA file missing at %s: %v", caPath, err)
	}

	// Verify EnvVars includes CA bundle vars.
	envStr := strings.Join(proxy.EnvVars(), "\n")
	for _, want := range []string{"SSL_CERT_FILE=" + caPath, "NODE_EXTRA_CA_CERTS=" + caPath, "REQUESTS_CA_BUNDLE=" + caPath} {
		if !strings.Contains(envStr, want) {
			t.Errorf("EnvVars() missing %q:\n%s", want, envStr)
		}
	}

	// Client trusts ONLY MCPGate's ephemeral CA (not upstream's cert directly!).
	client := newProxyHTTPClient(t, proxy.ProxyURL(), proxy.CACertPool())

	// 1. Clean HTTPS POST passes through MITM inspection to verified upstream TLS.
	resp, err := client.Post(upstream.URL+"/safe", "text/plain", strings.NewReader("benign encrypted payload"))
	if err != nil {
		t.Fatalf("clean MITM HTTPS POST failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "mitm-upstream-ok:benign encrypted payload" {
		t.Fatalf("unexpected MITM allow response: status=%d body=%q", resp.StatusCode, string(body))
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", upstreamHits.Load())
	}

	// 2. HTTPS POST exfiltrating a GitHub token is decrypted and BLOCKED with 403!
	ghToken := "ghp_" + strings.Repeat("Z9y8X7w6V", 4)
	resp, err = client.Post(upstream.URL+"/leak", "application/json", strings.NewReader(`{"token":"`+ghToken+`"}`))
	if err != nil {
		t.Fatalf("blocked MITM HTTPS POST transport error: %v", err)
	}
	assertForbiddenRule(t, resp, "MCP03-GITHUB-TOKEN")

	// Upstream must NOT have received the leaked secret!
	if upstreamHits.Load() != 1 {
		t.Fatalf("DLP-blocked HTTPS payload reached upstream! hits=%d, want 1", upstreamHits.Load())
	}

	evMu.Lock()
	if len(events) != 1 || events[0].Category != "dlp" || events[0].Action != "blocked" || events[0].RuleID != "MCP03-GITHUB-TOKEN" {
		t.Fatalf("expected 1 blocked DLP event for MITM HTTPS leak, got %+v", events)
	}
	evMu.Unlock()

	// 3. Close() must clean up the ephemeral CA file from disk.
	if err := proxy.Close(); err != nil {
		t.Fatalf("proxy.Close() failed: %v", err)
	}
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Errorf("ephemeral CA file %s was not removed on Close()", caPath)
	}
}

func TestHTTPSConnectMITMRedactAndCONNECTBlocksAndBodyCap(t *testing.T) {
	var lastBody atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer upstream.Close()

	upstreamPort := mustURLPort(t, upstream.URL)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	pol := &policy.Policy{
		Version: policy.CurrentVersion,
		Network: policy.NetworkPolicy{
			Enabled:            true,
			AllowPorts:         []int{443, upstreamPort},
			DenyDomains:        []string{"blocked.example"},
			BlockPrivateIPs:    true,
			BlockCloudMetadata: true,
			InspectTLS:         true,
		},
		DLP: policy.DLPPolicy{
			Enabled: true,
			Action:  policy.ActionRedact,
		},
	}
	scanner, err := dlp.NewScanner(pol.DLP, "")
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := New(Options{
		Policy:               pol,
		Scanner:              scanner,
		MaxBodyBytes:         128,
		UpstreamRootCAs:      upstreamRoots,
		AllowLoopbackForTest: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	client := newProxyHTTPClient(t, proxy.ProxyURL(), proxy.CACertPool())

	// 1. HTTPS MITM redact scrubs AWS key before forwarding upstream.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	resp, err := client.Post(upstream.URL+"/redact", "text/plain", strings.NewReader("id="+awsKey))
	if err != nil {
		t.Fatalf("HTTPS MITM redact failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, string(body))
	}
	gotUpstream := lastBody.Load().(string)
	if strings.Contains(gotUpstream, awsKey) || gotUpstream != "id=[MCPGATE-REDACTED:MCP03-AWS-ACCESS-KEY]" {
		t.Fatalf("HTTPS MITM upstream body not redacted: %q", gotUpstream)
	}

	// 2. Oversized body (> MaxBodyBytes) rejected with 413 Request Entity Too Large.
	resp, err = client.Post(upstream.URL+"/big", "text/plain", strings.NewReader(strings.Repeat("A", 256)))
	if err != nil {
		t.Fatalf("oversized HTTPS POST transport error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized payload status = %d, want 413", resp.StatusCode)
	}

	// 3. HTTPS CONNECT to cloud metadata IP or denied domain rejected at CONNECT handshake (403).
	if _, err := client.Get("https://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected CONNECT Forbidden for 169.254.169.254, got err=%v", err)
	}
	if _, err := client.Get("https://blocked.example/secret"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected CONNECT Forbidden for blocked.example, got err=%v", err)
	}
}

func newProxyHTTPClient(t *testing.T, proxyRawURL string, rootCAs *x509.CertPool) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyRawURL)
	if err != nil {
		t.Fatalf("parse proxy URL %q: %v", proxyRawURL, err)
	}
	tr := &http.Transport{
		Proxy: http.ProxyURL(u),
	}
	if rootCAs != nil {
		tr.TLSClientConfig = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func mustURLPort(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	_, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host:port %q: %v", u.Host, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return p
}

func assertForbiddenRule(t *testing.T, resp *http.Response, wantRuleID string) {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("invalid JSON error body %q: %v", string(body), err)
	}
	if payload["rule_id"] != wantRuleID {
		t.Fatalf("rule_id = %v, want %q; body=%s", payload["rule_id"], wantRuleID, string(body))
	}
}
