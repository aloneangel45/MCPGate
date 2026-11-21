package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// EphemeralCA is an in-memory ECDSA P-256 root Certificate Authority created solely
// for local TLS inspection (--inspect-tls). Only the public CA certificate is written
// to a temporary 0600 file for child processes; the private key never leaves memory.
type EphemeralCA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	certPath string

	mu    sync.RWMutex
	cache map[string]*tls.Certificate

	closeOnce sync.Once
	closeErr  error
}

// NewEphemeralCA generates a fresh in-memory ECDSA P-256 root CA and writes its
// public certificate PEM to a temporary file with 0600 permissions.
func NewEphemeralCA() (*EphemeralCA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CA public key: %w", err)
	}
	ski := sha256.Sum256(pubBytes)

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "MCPGate Ephemeral Inspection CA",
			Organization: []string{"MCPGate Local Egress Firewall"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:20],
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create ephemeral CA certificate: %w", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	tmpFile, err := os.CreateTemp("", "mcpgate-ca-*.pem")
	if err != nil {
		return nil, fmt.Errorf("create temp CA file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("chmod temp CA file: %w", err)
	}
	if _, err := tmpFile.Write(certPEM); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("write temp CA file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("close temp CA file: %w", err)
	}

	return &EphemeralCA{
		cert:     parsed,
		key:      priv,
		certPEM:  certPEM,
		certPath: tmpPath,
		cache:    make(map[string]*tls.Certificate),
	}, nil
}

// CertPath returns the path to the temporary public CA certificate PEM file.
func (ca *EphemeralCA) CertPath() string {
	if ca == nil {
		return ""
	}
	return ca.certPath
}

// CertPEM returns a copy of the public CA certificate PEM bytes.
func (ca *EphemeralCA) CertPEM() []byte {
	if ca == nil {
		return nil
	}
	out := make([]byte, len(ca.certPEM))
	copy(out, ca.certPEM)
	return out
}

// CertPool returns an x509.CertPool trusting this ephemeral CA.
func (ca *EphemeralCA) CertPool() *x509.CertPool {
	if ca == nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	return pool
}

// SignHost mints (or retrieves from cache) a leaf TLS certificate for the given host or IP.
func (ca *EphemeralCA) SignHost(host string) (*tls.Certificate, error) {
	clean := normalizeHost(host)
	if clean == "" {
		return nil, fmt.Errorf("cannot sign certificate for empty host")
	}

	ca.mu.RLock()
	if cached, ok := ca.cache[clean]; ok {
		ca.mu.RUnlock()
		return cached, nil
	}
	ca.mu.RUnlock()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %q: %w", clean, err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   clean,
			Organization: []string{"MCPGate Inspected Host"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.cert.SubjectKeyId,
	}

	if ip := net.ParseIP(clean); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{clean}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert for %q: %w", clean, err)
	}

	parsedLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert for %q: %w", clean, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        parsedLeaf,
	}

	ca.mu.Lock()
	// Check again in case another goroutine signed concurrently.
	if existing, ok := ca.cache[clean]; ok {
		ca.mu.Unlock()
		return existing, nil
	}
	ca.cache[clean] = tlsCert
	ca.mu.Unlock()

	return tlsCert, nil
}

// Close removes the temporary CA certificate PEM file from disk. Safe to call multiple times.
func (ca *EphemeralCA) Close() error {
	if ca == nil {
		return nil
	}
	ca.closeOnce.Do(func() {
		if ca.certPath != "" {
			err := os.Remove(ca.certPath)
			if err != nil && !os.IsNotExist(err) {
				ca.closeErr = err
			}
		}
	})
	return ca.closeErr
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if n.Sign() <= 0 {
		n = big.NewInt(1)
	}
	return n, nil
}
