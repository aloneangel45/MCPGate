package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/dlp"
	"github.com/aloneangel45/mcpgate/pkg/policy"
)

const (
	defaultMaxBodyBytes = 16 << 20 // 16 MiB
	defaultDialTimeout  = 15 * time.Second
)

type pinnedTargetKey struct{}

type pinnedTarget struct {
	ip   net.IP
	host string
	port int
}

// Options configures a local MCPGate HTTP/HTTPS Egress Firewall Proxy.
type Options struct {
	Policy          *policy.Policy
	Scanner         *dlp.Scanner
	ListenAddr      string
	SessionID       string
	ServerName      string
	MaxBodyBytes    int64
	DialTimeout     time.Duration
	OnEvent         func(policy.SecurityEvent)
	Resolver        *net.Resolver
	UpstreamRootCAs *x509.CertPool

	// AllowLoopbackForTest permits connecting to 127.0.0.1 / ::1 ONLY in unit tests
	// targeting local httptest servers. Must remain false in production.
	AllowLoopbackForTest bool
}

// Proxy is a local HTTP and HTTPS CONNECT egress firewall enforcing domain policy,
// SSRF/DNS-rebinding protection, and live DLP inspection.
type Proxy struct {
	opts       Options
	listener   net.Listener
	server     *http.Server
	ca         *EphemeralCA
	transport  *http.Transport
	baseCtx    context.Context
	baseCancel context.CancelFunc

	connsMu     sync.Mutex
	closed      bool
	activeConns map[net.Conn]struct{}

	closeOnce sync.Once
	closeErr  error
}

// New starts a local HTTP/HTTPS CONNECT egress proxy listening on Options.ListenAddr
// (defaulting to 127.0.0.1:0 for an ephemeral localhost port).
func New(opts Options) (*Proxy, error) {
	if opts.Policy == nil {
		return nil, fmt.Errorf("egress proxy requires a non-nil policy")
	}
	if strings.TrimSpace(opts.ListenAddr) == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultDialTimeout
	}

	var ca *EphemeralCA
	if opts.Policy.Network.InspectTLS {
		var err error
		ca, err = NewEphemeralCA()
		if err != nil {
			return nil, fmt.Errorf("init ephemeral inspection CA: %w", err)
		}
	}

	ln, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		if ca != nil {
			_ = ca.Close()
		}
		return nil, fmt.Errorf("listen on %s: %w", opts.ListenAddr, err)
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())

	p := &Proxy{
		opts:        opts,
		listener:    ln,
		ca:          ca,
		baseCtx:     baseCtx,
		baseCancel:  baseCancel,
		activeConns: make(map[net.Conn]struct{}),
	}

	p.transport = &http.Transport{
		Proxy:                 nil, // Never proxy recursively.
		DialContext:           p.dialPinnedTCP,
		DialTLSContext:        p.dialPinnedTLS,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
		BaseContext: func(net.Listener) context.Context {
			return p.baseCtx
		},
	}

	go func() {
		_ = p.server.Serve(ln)
	}()

	return p, nil
}

// ProxyURL returns the local proxy URL (e.g. "http://127.0.0.1:54321").
func (p *Proxy) ProxyURL() string {
	if p == nil || p.listener == nil {
		return ""
	}
	return "http://" + p.listener.Addr().String()
}

// CACertPath returns the temporary CA PEM file path when InspectTLS is enabled, or "".
func (p *Proxy) CACertPath() string {
	if p == nil || p.ca == nil {
		return ""
	}
	return p.ca.CertPath()
}

// CACertPEM returns the ephemeral CA PEM bytes when InspectTLS is enabled, or nil.
func (p *Proxy) CACertPEM() []byte {
	if p == nil || p.ca == nil {
		return nil
	}
	return p.ca.CertPEM()
}

// CACertPool returns a CertPool trusting the ephemeral CA when InspectTLS is enabled, or nil.
func (p *Proxy) CACertPool() *x509.CertPool {
	if p == nil || p.ca == nil {
		return nil
	}
	return p.ca.CertPool()
}

// EnvVars returns environment variables to force child MCP processes through this proxy.
func (p *Proxy) EnvVars() []string {
	proxyURL := p.ProxyURL()
	vars := []string{
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"NO_PROXY=",
		"no_proxy=",
	}
	if p.ca != nil && p.ca.CertPath() != "" {
		caPath := p.ca.CertPath()
		vars = append(vars,
			"SSL_CERT_FILE="+caPath,
			"NODE_EXTRA_CA_CERTS="+caPath,
			"REQUESTS_CA_BUNDLE="+caPath,
		)
	}
	return vars
}

// Close shuts down the proxy listener, terminates active tunnels, and removes any ephemeral CA file.
func (p *Proxy) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		var errs []error

		// Cancel in-flight dials and upstream round-trips first so shutdown completes promptly.
		if p.baseCancel != nil {
			p.baseCancel()
		}

		// Mark closed and force-close any hijacked CONNECT tunnel connections.
		p.connsMu.Lock()
		p.closed = true
		for c := range p.activeConns {
			_ = c.Close()
		}
		p.activeConns = make(map[net.Conn]struct{})
		p.connsMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if p.server != nil {
			if err := p.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				_ = p.server.Close()
			}
		}

		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}

		if p.ca != nil {
			if err := p.ca.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) > 0 {
			p.closeErr = errors.Join(errs...)
		}
	})
	return p.closeErr
}

func (p *Proxy) trackConn(c net.Conn) bool {
	p.connsMu.Lock()
	if p.closed {
		p.connsMu.Unlock()
		_ = c.Close()
		return false
	}
	p.activeConns[c] = struct{}{}
	p.connsMu.Unlock()
	return true
}

func (p *Proxy) untrackConn(c net.Conn) {
	p.connsMu.Lock()
	delete(p.activeConns, c)
	p.connsMu.Unlock()
}

func (p *Proxy) emitEvent(ev policy.SecurityEvent) {
	if p.opts.OnEvent == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.SessionID == "" {
		ev.SessionID = p.opts.SessionID
	}
	if ev.Server == "" {
		ev.Server = p.opts.ServerName
	}
	p.opts.OnEvent(ev)
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	rawHost := r.URL.Host
	if rawHost == "" {
		rawHost = r.Host
	}
	defaultPort := 80
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		writeJSONError(w, http.StatusBadRequest, map[string]any{
			"error":  "unsupported proxy URL scheme",
			"reason": fmt.Sprintf("unsupported scheme %q (expected http or https)", scheme),
		})
		return
	}
	if scheme == "https" {
		defaultPort = 443
	}

	host, port, hostPort, err := parseHostPort(rawHost, defaultPort)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, map[string]any{
			"error":  "invalid proxy target host",
			"reason": err.Error(),
		})
		return
	}

	// Guard against Host-header domain fronting when r.Host differs from r.URL.Host.
	if r.Host != "" && r.URL.Host != "" {
		hdrHost, hdrPort, _, hdrErr := parseHostPort(r.Host, port)
		if hdrErr == nil && hdrHost != host {
			if decHdr := p.opts.Policy.EvaluateDomain(hdrHost, hdrPort); decHdr.Action != policy.ActionAllow {
				p.emitEvent(policy.SecurityEvent{
					Category: "egress",
					Severity: decHdr.Severity,
					Action:   "blocked",
					RuleID:   decHdr.RuleID,
					Target:   hdrHost,
					Message:  fmt.Sprintf("Host header %q mismatch blocked: %s", r.Host, decHdr.Reason),
					Metadata: map[string]string{"method": r.Method, "scheme": scheme, "url_host": hostPort},
				})
				writeJSONError(w, http.StatusForbidden, map[string]any{
					"error":   "blocked by MCPGate egress policy",
					"rule_id": decHdr.RuleID,
					"reason":  decHdr.Reason,
					"target":  hdrHost,
				})
				return
			}
			if blocked, ruleID, reason := ValidateTargetHost(hdrHost, p.opts.Policy.Network); blocked {
				p.emitEvent(policy.SecurityEvent{
					Category: "ssrf",
					Severity: severityForSSRFRule(ruleID),
					Action:   "blocked",
					RuleID:   ruleID,
					Target:   hdrHost,
					Message:  reason,
					Metadata: map[string]string{"method": r.Method, "scheme": scheme, "url_host": hostPort},
				})
				writeJSONError(w, http.StatusForbidden, map[string]any{
					"error":   "blocked by MCPGate SSRF guard",
					"rule_id": ruleID,
					"reason":  reason,
					"target":  hdrHost,
				})
				return
			}
		}
	}

	// 1. Domain / port / airgapped policy check.
	dec := p.opts.Policy.EvaluateDomain(host, port)
	if dec.Action != policy.ActionAllow {
		p.emitEvent(policy.SecurityEvent{
			Category: "egress",
			Severity: dec.Severity,
			Action:   "blocked",
			RuleID:   dec.RuleID,
			Target:   hostPort,
			Message:  dec.Reason,
			Metadata: map[string]string{"method": r.Method, "scheme": scheme},
		})
		writeJSONError(w, http.StatusForbidden, map[string]any{
			"error":   "blocked by MCPGate egress policy",
			"rule_id": dec.RuleID,
			"reason":  dec.Reason,
			"target":  hostPort,
		})
		return
	}

	// 2. SSRF & DNS-rebinding IP validation and pinning.
	pinnedIP, blockErr, resolveErr := resolveAndPinIP(r.Context(), p.opts.Resolver, host, p.opts.Policy.Network, p.opts.AllowLoopbackForTest)
	if blockErr != nil {
		p.emitEvent(policy.SecurityEvent{
			Category: blockErr.Category,
			Severity: blockErr.Severity,
			Action:   "blocked",
			RuleID:   blockErr.RuleID,
			Target:   hostPort,
			Message:  blockErr.Reason,
			Metadata: map[string]string{"method": r.Method, "scheme": scheme},
		})
		writeJSONError(w, http.StatusForbidden, map[string]any{
			"error":   "blocked by MCPGate SSRF guard",
			"rule_id": blockErr.RuleID,
			"reason":  blockErr.Reason,
			"target":  hostPort,
		})
		return
	}
	if resolveErr != nil {
		writeJSONError(w, http.StatusBadGateway, map[string]any{
			"error":  "upstream DNS resolution failed",
			"reason": resolveErr.Error(),
			"target": hostPort,
		})
		return
	}

	// 3. Clone request and perform DLP inspection / redaction.
	outURL := *r.URL
	outURL.Scheme = scheme
	outURL.Host = hostPort

	outReq := r.Clone(context.WithValue(r.Context(), pinnedTargetKey{}, pinnedTarget{
		ip:   pinnedIP,
		host: host,
		port: port,
	}))
	outReq.RequestURI = ""
	outReq.URL = &outURL
	outReq.Host = r.Host
	if outReq.Host == "" {
		outReq.Host = hostPort
	}
	removeHopByHopHeaders(outReq.Header)

	bodyBytes, findings, blocked, statusCode, inspectErr := p.inspectRequest(outReq, hostPort)
	if inspectErr != nil {
		writeJSONError(w, statusCode, map[string]any{
			"error":  "request inspection failed",
			"reason": inspectErr.Error(),
		})
		return
	}
	if blocked {
		writeJSONError(w, http.StatusForbidden, map[string]any{
			"error":          "blocked by MCPGate DLP",
			"rule_id":        findings[0].RuleID,
			"findings_count": len(findings),
			"reason":         fmt.Sprintf("detected %d secret/PII finding(s) matching %s", len(findings), findings[0].RuleID),
			"target":         hostPort,
		})
		return
	}

	if len(bodyBytes) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		outReq.ContentLength = int64(len(bodyBytes))
		outReq.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	} else {
		outReq.Body = http.NoBody
		outReq.ContentLength = 0
		outReq.Header.Del("Content-Length")
	}

	// 4. Forward request to pinned IP.
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, map[string]any{
			"error":  "upstream request failed",
			"reason": err.Error(),
			"target": hostPort,
		})
		return
	}
	defer resp.Body.Close()

	if p.opts.Policy.Audit.LogAllowed {
		p.emitEvent(policy.SecurityEvent{
			Category: "egress",
			Severity: policy.SeverityInfo,
			Action:   "allowed",
			RuleID:   dec.RuleID,
			Target:   hostPort,
			Message:  fmt.Sprintf("%s %s -> %d", r.Method, hostPort, resp.StatusCode),
			Metadata: map[string]string{"method": r.Method, "pinned_ip": pinnedIP.String()},
		})
	}

	copyHeaders(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	rawHost := r.Host
	if rawHost == "" {
		rawHost = r.URL.Host
	}

	host, port, hostPort, err := parseHostPort(rawHost, 443)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, map[string]any{
			"error":  "invalid CONNECT target",
			"reason": err.Error(),
		})
		return
	}

	// 1. Domain / port / airgapped policy check.
	dec := p.opts.Policy.EvaluateDomain(host, port)
	if dec.Action != policy.ActionAllow {
		p.emitEvent(policy.SecurityEvent{
			Category: "egress",
			Severity: dec.Severity,
			Action:   "blocked",
			RuleID:   dec.RuleID,
			Target:   hostPort,
			Message:  dec.Reason,
			Metadata: map[string]string{"method": http.MethodConnect},
		})
		writeJSONError(w, http.StatusForbidden, map[string]any{
			"error":   "blocked by MCPGate egress policy",
			"rule_id": dec.RuleID,
			"reason":  dec.Reason,
			"target":  hostPort,
		})
		return
	}

	// 2. SSRF & DNS-rebinding IP validation and pinning.
	pinnedIP, blockErr, resolveErr := resolveAndPinIP(r.Context(), p.opts.Resolver, host, p.opts.Policy.Network, p.opts.AllowLoopbackForTest)
	if blockErr != nil {
		p.emitEvent(policy.SecurityEvent{
			Category: blockErr.Category,
			Severity: blockErr.Severity,
			Action:   "blocked",
			RuleID:   blockErr.RuleID,
			Target:   hostPort,
			Message:  blockErr.Reason,
			Metadata: map[string]string{"method": http.MethodConnect},
		})
		writeJSONError(w, http.StatusForbidden, map[string]any{
			"error":   "blocked by MCPGate SSRF guard",
			"rule_id": blockErr.RuleID,
			"reason":  blockErr.Reason,
			"target":  hostPort,
		})
		return
	}
	if resolveErr != nil {
		writeJSONError(w, http.StatusBadGateway, map[string]any{
			"error":  "upstream DNS resolution failed",
			"reason": resolveErr.Error(),
			"target": hostPort,
		})
		return
	}

	if p.opts.Policy.Network.InspectTLS && p.ca != nil {
		p.handleConnectMITM(w, r, host, port, hostPort, pinnedIP, dec)
		return
	}

	p.handleConnectTunnel(w, r, hostPort, pinnedIP, port, dec)
}

func (p *Proxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request, hostPort string, pinnedIP net.IP, port int, dec policy.Decision) {
	dialer := &net.Dialer{
		Timeout:   p.opts.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	upstreamConn, err := dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(pinnedIP.String(), strconv.Itoa(port)))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, map[string]any{
			"error":  "failed to connect to upstream",
			"reason": err.Error(),
			"target": hostPort,
		})
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		writeJSONError(w, http.StatusInternalServerError, map[string]any{
			"error": "proxy hijacking not supported",
		})
		return
	}

	rawClientConn, brw, err := hj.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		return
	}

	if !p.trackConn(rawClientConn) {
		_ = upstreamConn.Close()
		return
	}
	if !p.trackConn(upstreamConn) {
		p.untrackConn(rawClientConn)
		_ = rawClientConn.Close()
		return
	}
	defer func() {
		p.untrackConn(rawClientConn)
		p.untrackConn(upstreamConn)
		_ = rawClientConn.Close()
		_ = upstreamConn.Close()
	}()

	if _, err := io.WriteString(rawClientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	clientConn := wrapBufferedConn(rawClientConn, brw.Reader)

	if p.opts.Policy.Audit.LogAllowed {
		p.emitEvent(policy.SecurityEvent{
			Category: "egress",
			Severity: policy.SeverityInfo,
			Action:   "allowed",
			RuleID:   dec.RuleID,
			Target:   hostPort,
			Message:  fmt.Sprintf("CONNECT tunnel established to %s (pinned %s)", hostPort, pinnedIP.String()),
			Metadata: map[string]string{"method": http.MethodConnect, "pinned_ip": pinnedIP.String()},
		})
	}

	// Bidirectional copy; close both ends as soon as either side terminates.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, clientConn)
		closeWrite(upstreamConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstreamConn)
		closeWrite(rawClientConn)
	}()
	wg.Wait()
}

func (p *Proxy) handleConnectMITM(w http.ResponseWriter, r *http.Request, host string, port int, hostPort string, pinnedIP net.IP, dec policy.Decision) {
	leafCert, err := p.ca.SignHost(host)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, map[string]any{
			"error":  "failed to mint inspection certificate",
			"reason": err.Error(),
		})
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, map[string]any{
			"error": "proxy hijacking not supported",
		})
		return
	}

	rawClientConn, brw, err := hj.Hijack()
	if err != nil {
		return
	}

	if !p.trackConn(rawClientConn) {
		return
	}
	defer func() {
		p.untrackConn(rawClientConn)
		_ = rawClientConn.Close()
	}()

	if _, err := io.WriteString(rawClientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	clientConn := wrapBufferedConn(rawClientConn, brw.Reader)
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsClient.HandshakeContext(r.Context()); err != nil {
		return
	}
	defer tlsClient.Close()

	reader := bufio.NewReader(tlsClient)
	for {
		_ = tlsClient.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = tlsClient.SetReadDeadline(time.Time{})

		reqHost := req.Host
		if reqHost == "" {
			reqHost = hostPort
		} else if hdrHost, hdrPort, _, hdrErr := parseHostPort(reqHost, port); hdrErr == nil && hdrHost != host {
			// Guard against TLS MITM domain fronting via mismatched inner Host header.
			if decHdr := p.opts.Policy.EvaluateDomain(hdrHost, hdrPort); decHdr.Action != policy.ActionAllow {
				_ = req.Body.Close()
				p.emitEvent(policy.SecurityEvent{
					Category: "egress",
					Severity: decHdr.Severity,
					Action:   "blocked",
					RuleID:   decHdr.RuleID,
					Target:   hdrHost,
					Message:  fmt.Sprintf("inner HTTPS Host header %q blocked: %s", reqHost, decHdr.Reason),
					Metadata: map[string]string{"method": req.Method, "connect_target": hostPort},
				})
				_ = writeRawJSONResponse(tlsClient, http.StatusForbidden, map[string]any{
					"error":   "blocked by MCPGate egress policy",
					"rule_id": decHdr.RuleID,
					"reason":  decHdr.Reason,
					"target":  hdrHost,
				})
				return
			}
			if blocked, ruleID, reason := ValidateTargetHost(hdrHost, p.opts.Policy.Network); blocked {
				_ = req.Body.Close()
				p.emitEvent(policy.SecurityEvent{
					Category: "ssrf",
					Severity: severityForSSRFRule(ruleID),
					Action:   "blocked",
					RuleID:   ruleID,
					Target:   hdrHost,
					Message:  reason,
					Metadata: map[string]string{"method": req.Method, "connect_target": hostPort},
				})
				_ = writeRawJSONResponse(tlsClient, http.StatusForbidden, map[string]any{
					"error":   "blocked by MCPGate SSRF guard",
					"rule_id": ruleID,
					"reason":  reason,
					"target":  hdrHost,
				})
				return
			}
		}

		outURL := *req.URL
		outURL.Scheme = "https"
		outURL.Host = hostPort

		outCtx := context.WithValue(p.baseCtx, pinnedTargetKey{}, pinnedTarget{
			ip:   pinnedIP,
			host: host,
			port: port,
		})
		outReq := req.Clone(outCtx)
		outReq.RequestURI = ""
		outReq.URL = &outURL
		outReq.Host = reqHost
		removeHopByHopHeaders(outReq.Header)

		bodyBytes, findings, blocked, statusCode, inspectErr := p.inspectRequest(outReq, hostPort)
		_ = req.Body.Close()

		if inspectErr != nil {
			_ = writeRawJSONResponse(tlsClient, statusCode, map[string]any{
				"error":  "request inspection failed",
				"reason": inspectErr.Error(),
			})
			return
		}
		if blocked {
			_ = writeRawJSONResponse(tlsClient, http.StatusForbidden, map[string]any{
				"error":          "blocked by MCPGate DLP",
				"rule_id":        findings[0].RuleID,
				"findings_count": len(findings),
				"reason":         fmt.Sprintf("detected %d secret/PII finding(s) matching %s", len(findings), findings[0].RuleID),
				"target":         hostPort,
			})
			return
		}

		if len(bodyBytes) > 0 {
			outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			outReq.ContentLength = int64(len(bodyBytes))
			outReq.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		} else {
			outReq.Body = http.NoBody
			outReq.ContentLength = 0
			outReq.Header.Del("Content-Length")
		}

		resp, err := p.transport.RoundTrip(outReq)
		if err != nil {
			_ = writeRawJSONResponse(tlsClient, http.StatusBadGateway, map[string]any{
				"error":  "upstream TLS request failed",
				"reason": err.Error(),
				"target": hostPort,
			})
			return
		}

		if p.opts.Policy.Audit.LogAllowed {
			p.emitEvent(policy.SecurityEvent{
				Category: "egress",
				Severity: policy.SeverityInfo,
				Action:   "allowed",
				RuleID:   dec.RuleID,
				Target:   hostPort,
				Message:  fmt.Sprintf("HTTPS %s %s -> %d (TLS inspected)", req.Method, hostPort, resp.StatusCode),
				Metadata: map[string]string{"method": req.Method, "pinned_ip": pinnedIP.String(), "tls_inspected": "true"},
			})
		}

		removeHopByHopHeaders(resp.Header)
		writeErr := resp.Write(tlsClient)
		_ = resp.Body.Close()
		if writeErr != nil || req.Close || resp.Close {
			return
		}
	}
}

// inspectRequest reads the request body (capped at MaxBodyBytes) and runs DLP scanning
// across URL, headers, and body. When DLP action is redact, it mutates req in-place and
// returns the scrubbed body bytes.
func (p *Proxy) inspectRequest(req *http.Request, target string) (bodyBytes []byte, findings []dlp.Finding, blocked bool, errStatus int, err error) {
	if req.Body != nil && req.Body != http.NoBody {
		limited := io.LimitReader(req.Body, p.opts.MaxBodyBytes+1)
		data, readErr := io.ReadAll(limited)
		if readErr != nil {
			return nil, nil, false, http.StatusBadRequest, fmt.Errorf("read request body: %w", readErr)
		}
		if int64(len(data)) > p.opts.MaxBodyBytes {
			return nil, nil, false, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d byte inspection limit", p.opts.MaxBodyBytes)
		}
		bodyBytes = data
	}

	if !p.opts.Policy.DLP.Enabled || p.opts.Scanner == nil {
		return bodyBytes, nil, false, 0, nil
	}

	var allFindings []dlp.Finding

	// 1. Scan full URL (path + query).
	if req.URL != nil {
		urlFindings := p.opts.Scanner.Scan(req.URL.String())
		allFindings = append(allFindings, urlFindings...)
	}

	// 2. Scan request headers in deterministic order.
	headerKeys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)
	for _, k := range headerKeys {
		for _, v := range req.Header[k] {
			if hf := p.opts.Scanner.Scan(v); len(hf) > 0 {
				allFindings = append(allFindings, hf...)
			}
		}
	}

	// 3. Scan request body.
	if len(bodyBytes) > 0 {
		bodyFindings := p.opts.Scanner.Scan(string(bodyBytes))
		allFindings = append(allFindings, bodyFindings...)
	}

	if len(allFindings) == 0 {
		return bodyBytes, nil, false, 0, nil
	}

	action := p.opts.Policy.DLP.Action
	if action == "" {
		action = policy.ActionBlock
	}
	maxSev := highestSeverity(allFindings)
	meta := map[string]string{
		"method":         req.Method,
		"match_preview":  allFindings[0].MatchPreview,
		"sha256_prefix":  allFindings[0].SHA256Prefix,
		"findings_count": strconv.Itoa(len(allFindings)),
	}

	switch action {
	case policy.ActionBlock, policy.ActionDeny:
		p.emitEvent(policy.SecurityEvent{
			Category: "dlp",
			Severity: maxSev,
			Action:   "blocked",
			RuleID:   allFindings[0].RuleID,
			Target:   target,
			Message:  fmt.Sprintf("blocked outbound %s to %s: %s (%d finding(s))", req.Method, target, allFindings[0].Name, len(allFindings)),
			Metadata: meta,
		})
		return nil, allFindings, true, http.StatusForbidden, nil

	case policy.ActionRedact:
		if req.URL != nil {
			if req.URL.RawQuery != "" {
				if redactedQ, qf := p.opts.Scanner.Redact(req.URL.RawQuery); len(qf) > 0 {
					req.URL.RawQuery = redactedQ
				}
			}
			if req.URL.Path != "" {
				if redactedP, pf := p.opts.Scanner.Redact(req.URL.Path); len(pf) > 0 {
					req.URL.Path = redactedP
					req.URL.RawPath = ""
				}
			}
		}
		for _, k := range headerKeys {
			vals := req.Header[k]
			for i, v := range vals {
				if redactedV, hf := p.opts.Scanner.Redact(v); len(hf) > 0 {
					vals[i] = redactedV
				}
			}
		}
		if len(bodyBytes) > 0 {
			if redactedBody, bf := p.opts.Scanner.Redact(string(bodyBytes)); len(bf) > 0 {
				bodyBytes = []byte(redactedBody)
			}
		}
		p.emitEvent(policy.SecurityEvent{
			Category: "dlp",
			Severity: maxSev,
			Action:   "redacted",
			RuleID:   allFindings[0].RuleID,
			Target:   target,
			Message:  fmt.Sprintf("redacted %d secret/PII finding(s) in outbound %s to %s", len(allFindings), req.Method, target),
			Metadata: meta,
		})
		return bodyBytes, allFindings, false, 0, nil

	case policy.ActionWarn:
		p.emitEvent(policy.SecurityEvent{
			Category: "dlp",
			Severity: maxSev,
			Action:   "warned",
			RuleID:   allFindings[0].RuleID,
			Target:   target,
			Message:  fmt.Sprintf("detected %d secret/PII finding(s) in outbound %s to %s (warn mode)", len(allFindings), req.Method, target),
			Metadata: meta,
		})
		return bodyBytes, allFindings, false, 0, nil

	default:
		p.emitEvent(policy.SecurityEvent{
			Category: "dlp",
			Severity: maxSev,
			Action:   "blocked",
			RuleID:   allFindings[0].RuleID,
			Target:   target,
			Message:  fmt.Sprintf("blocked outbound %s to %s: %s", req.Method, target, allFindings[0].Name),
			Metadata: meta,
		})
		return nil, allFindings, true, http.StatusForbidden, nil
	}
}

func (p *Proxy) dialPinnedTCP(ctx context.Context, network, _ string) (net.Conn, error) {
	pt, ok := ctx.Value(pinnedTargetKey{}).(pinnedTarget)
	if !ok || pt.ip == nil || pt.port <= 0 {
		return nil, fmt.Errorf("refusing unpinned outbound dial")
	}
	dialer := &net.Dialer{
		Timeout:   p.opts.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(pt.ip.String(), strconv.Itoa(pt.port)))
}

func (p *Proxy) dialPinnedTLS(ctx context.Context, network, _ string) (net.Conn, error) {
	pt, ok := ctx.Value(pinnedTargetKey{}).(pinnedTarget)
	if !ok || pt.ip == nil || pt.port <= 0 {
		return nil, fmt.Errorf("refusing unpinned outbound TLS dial")
	}
	rawConn, err := p.dialPinnedTCP(ctx, network, "")
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		ServerName: pt.host,
		RootCAs:    p.opts.UpstreamRootCAs,
		MinVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func parseHostPort(rawHost string, defaultPort int) (host string, port int, hostPort string, err error) {
	trimmed := strings.TrimSpace(rawHost)
	if trimmed == "" {
		return "", 0, "", fmt.Errorf("empty host")
	}

	if h, portStr, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
		pNum, convErr := strconv.Atoi(portStr)
		if convErr != nil || pNum < 1 || pNum > 65535 {
			return "", 0, "", fmt.Errorf("invalid port %q", portStr)
		}
		cleanHost := normalizeHost(h)
		if cleanHost == "" {
			return "", 0, "", fmt.Errorf("empty hostname in %q", rawHost)
		}
		return cleanHost, pNum, net.JoinHostPort(cleanHost, strconv.Itoa(pNum)), nil
	}

	cleanHost := normalizeHost(trimmed)
	if cleanHost == "" {
		return "", 0, "", fmt.Errorf("empty hostname in %q", rawHost)
	}
	return cleanHost, defaultPort, net.JoinHostPort(cleanHost, strconv.Itoa(defaultPort)), nil
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	if connHeader := h.Get("Connection"); connHeader != "" {
		for _, field := range strings.Split(connHeader, ",") {
			if name := strings.TrimSpace(field); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func writeJSONError(w http.ResponseWriter, statusCode int, payload map[string]any) {
	data, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(statusCode)
	_, _ = w.Write(data)
}

func writeRawJSONResponse(conn net.Conn, statusCode int, payload map[string]any) error {
	data, _ := json.Marshal(payload)
	resp := &http.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}, "Connection": {"close"}},
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
		Close:         true,
	}
	return resp.Write(conn)
}

func highestSeverity(findings []dlp.Finding) policy.Severity {
	rank := func(s policy.Severity) int {
		switch s {
		case policy.SeverityCritical:
			return 5
		case policy.SeverityHigh:
			return 4
		case policy.SeverityMedium:
			return 3
		case policy.SeverityLow:
			return 2
		default:
			return 1
		}
	}
	best := policy.SeverityInfo
	for _, f := range findings {
		if rank(f.Severity) > rank(best) {
			best = f.Severity
		}
	}
	return best
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func wrapBufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	if br == nil || br.Buffered() == 0 {
		return c
	}
	return &bufferedConn{Conn: c, r: io.MultiReader(br, c)}
}
