package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	eotocDirName       = ".eotoc"
	serverCertFile     = "server.crt"
	serverKeyFile      = "server.key"
	trustedPeersFile   = "trusted_peers.json"
	serverKeyBits      = 3072
	fingerprintLength  = 64
)

type TrustStore struct {
	mu    sync.RWMutex
	Peers map[string]string `json:"peers"`
	path  string
}

func eotocDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(home, eotocDirName)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	return dir, nil
}

func NewTrustStore() (*TrustStore, error) {
	dir, err := eotocDirectory()
	if err != nil {
		return nil, err
	}

	store := &TrustStore{
		Peers: make(map[string]string),
		path:  filepath.Join(dir, trustedPeersFile),
	}

	if err := store.load(); err != nil {
		return nil, err
	}

	return store, nil
}

func (t *TrustStore) load() error {
	data, err := os.ReadFile(t.path)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	var stored struct {
		Peers map[string]string `json:"peers"`
	}

	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("invalid trust store: %w", err)
	}

	for address, fingerprint := range stored.Peers {
		if len(fingerprint) != fingerprintLength {
			continue
		}

		t.Peers[address] = strings.ToUpper(fingerprint)
	}

	return nil
}

func (t *TrustStore) save() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	data, err := json.MarshalIndent(
		struct {
			Peers map[string]string `json:"peers"`
		}{
			Peers: t.Peers,
		},
		"",
		"  ",
	)
	if err != nil {
		return err
	}

	temp := t.path + ".tmp"

	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}

	return os.Rename(temp, t.path)
}

func (t *TrustStore) Get(address string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fingerprint, ok := t.Peers[address]
	return fingerprint, ok
}

func (t *TrustStore) Trust(address, fingerprint string) error {
	fingerprint = strings.ToUpper(fingerprint)

	if len(fingerprint) != fingerprintLength {
		return errors.New("invalid fingerprint")
	}

	t.mu.Lock()
	t.Peers[address] = fingerprint
	t.mu.Unlock()

	return t.save()
}

func (t *TrustStore) Remove(address string) error {
	t.mu.Lock()
	delete(t.Peers, address)
	t.mu.Unlock()

	return t.save()
}

func fingerprintCertificate(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)

	hexString := strings.ToUpper(hex.EncodeToString(sum[:]))

	var parts []string

	for i := 0; i < len(hexString); i += 2 {
		parts = append(parts, hexString[i:i+2])
	}

	return strings.Join(parts, ":")
}

func generateServerCertificate() (tls.Certificate, error) {
	dir, err := eotocDirectory()
	if err != nil {
		return tls.Certificate{}, err
	}

	certPath := filepath.Join(dir, serverCertFile)
	keyPath := filepath.Join(dir, serverKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return tls.LoadX509KeyPair(certPath, keyPath)
		}
	}

	fmt.Println("[*] Creating EOTOC server identity...")

	privateKey, err := rsa.GenerateKey(rand.Reader, serverKeyBits)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"generate private key: %w",
			err,
		)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,

		Subject: pkix.Name{
			CommonName: "EOTOC Server",
		},

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.AddDate(10, 0, 0),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,

		DNSNames: []string{
			"localhost",
		},
	}

	// Add common local IP addresses.
	template.IPAddresses = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"create certificate: %w",
			err,
		)
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
	)

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		},
	)

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}

	fmt.Println("[+] Server identity created.")
	fmt.Println("[+] Certificate fingerprint:")

	cert, err := x509.ParseCertificate(der)
	if err == nil {
		fmt.Println(fingerprintCertificate(cert))
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

func validatePinnedCertificate(
	state tls.ConnectionState,
	expectedFingerprint string,
) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("server did not provide a certificate")
	}

	cert := state.PeerCertificates[0]

	now := time.Now()

	if now.Before(cert.NotBefore) ||
		now.After(cert.NotAfter) {
		return errors.New("server certificate is outside its validity period")
	}

	// The EOTOC server uses a self-signed certificate.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return errors.New("server certificate is not self-signed")
	}

	actual := fingerprintCertificate(cert)

	if expectedFingerprint != "" &&
		!strings.EqualFold(actual, expectedFingerprint) {
		return fmt.Errorf(
			"server identity changed: expected %s, received %s",
			expectedFingerprint,
			actual,
		)
	}

	return nil
}

func clientTLSConfig(
	address string,
	trustedFingerprint string,
) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		// EOTOC uses certificate fingerprint pinning.
		//
		// The certificate is self-signed, so the normal public-CA
		// verification chain cannot be used here.
		//
		// VerifyConnection performs the custom validation.
		InsecureSkipVerify: true,

		ServerName: "",

		VerifyConnection: func(
			state tls.ConnectionState,
		) error {
			return validatePinnedCertificate(
				state,
				trustedFingerprint,
			)
		},
	}
}

func serverTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		Certificates: []tls.Certificate{
			cert,
		},
	}
}