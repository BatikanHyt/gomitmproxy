package cert

import (
	"crypto/rand"
	"crypto/rsa"
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

// CertManager manages certificate generation and caching for MITM proxy
type CertManager struct {
	rootCaCert *x509.Certificate
	rootCaKey  *rsa.PrivateKey
	certStore  map[string]*tls.Certificate
	mu         sync.RWMutex
}

// NewCertManager creates a new certificate manager
// If rootCaCert or rootCaKey are nil, it will generate a self-signed CA
func NewCertManager(rootCaCert *x509.Certificate, rootCaKey *rsa.PrivateKey) (*CertManager, error) {
	manager := &CertManager{}
	if rootCaCert == nil || rootCaKey == nil {
		ca, key, err := CreateSelfSignedCA("")
		if err != nil {
			return nil, fmt.Errorf("failed to create self-signed CA: %w", err)
		}
		rootCaCert = ca
		rootCaKey = key
	}
	manager.rootCaCert = rootCaCert
	manager.rootCaKey = rootCaKey
	manager.certStore = make(map[string]*tls.Certificate)
	return manager, nil
}

// CreateGetCertHost creates or retrieves a certificate for the given host
func (cm *CertManager) CreateGetCertHost(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	cert, ok := cm.certStore[host]
	cm.mu.RUnlock()
	if ok {
		return cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: host, Organization: []string{host}},
		NotBefore:             time.Now().Add(-time.Hour * 72),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certData, err := x509.CreateCertificate(rand.Reader, &template, cm.rootCaCert, &key.PublicKey, cm.rootCaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}
	cm.mu.Lock()
	cm.certStore[host] = &tlsCert
	cm.mu.Unlock()

	return &tlsCert, nil
}

// ClearCache clears the certificate cache
func (cm *CertManager) ClearCache() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.certStore = make(map[string]*tls.Certificate)
}

// SaveCertToFile saves a root CA Cert to a PEM file
func (cm *CertManager) SaveCertToFile(filename string) error {
	return SaveCertificate(cm.rootCaCert, filename)
}

// SavePrivateKeyToFile saves a root private key to a PEM file
func (cm *CertManager) SavePrivateKeyToFile(filename string) error {
	return SavePrivateRsaKey(cm.rootCaKey, filename)
}

// CreateSelfSignedCA creates a self-signed Certificate Authority
func CreateSelfSignedCA(commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if commonName == "" {
		commonName = "gomitmproxy"
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{commonName}},
		NotBefore:             time.Now().Add(-time.Hour * 72),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
			x509.ExtKeyUsageNetscapeServerGatedCrypto,
		},
	}

	certData, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, key, nil
}

// LoadCertificate loads an X.509 certificate from a file and returns a parsed *x509.Certificate
func LoadCertificate(certFile string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// SaveCertificate saves a cert to a PEM file
func SaveCertificate(cert *x509.Certificate, filename string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(certPEM)
	if err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

// LoadRSAPrivateKey loads an RSA private key from a PEM file
func LoadRSAPrivateKey(keyFile string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try PKCS#1 format
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8 format
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// SavePrivateRsaKey saves a private key to a PEM file
func SavePrivateRsaKey(key *rsa.PrivateKey, filename string) error {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

func LoadOrCreateCa(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, certErr := LoadCertificate(certFile)
	key, keyErr := LoadRSAPrivateKey(keyFile)

	if certErr == nil && keyErr == nil {
		return cert, key, nil
	}

	cert, key, err := CreateSelfSignedCA("gomitmproxy")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create self-signed CA: %w", err)
	}

	if err := SaveCertificate(cert, certFile); err != nil {
		return nil, nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	if err := SavePrivateRsaKey(key, keyFile); err != nil {
		return nil, nil, fmt.Errorf("failed to save private key: %w", err)
	}

	return cert, key, nil
}
