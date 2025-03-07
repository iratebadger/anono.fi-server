package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// Common PEM block types
const (
	CertificatePEMBlockType = "CERTIFICATE"
	CSRPEMBlockType         = "CERTIFICATE REQUEST"
	RSAPrivateKeyBlockType  = "RSA PRIVATE KEY"
)

// GenerateRSAKey generates an RSA private key with the specified bit size
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// MarshalPrivateKeyToPEM converts an RSA private key to PEM format
func MarshalPrivateKeyToPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := &pem.Block{
		Type:  RSAPrivateKeyBlockType,
		Bytes: privateKeyBytes,
	}
	
	var privateKeyPEM bytes.Buffer
	if err := pem.Encode(&privateKeyPEM, privatePEM); err != nil {
		return nil, err
	}
	
	return privateKeyPEM.Bytes(), nil
}

// ParsePrivateKeyFromPEM parses a PEM encoded RSA private key
func ParsePrivateKeyFromPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != RSAPrivateKeyBlockType {
		return nil, errors.New("failed to parse PEM block containing private key")
	}
	
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// CreateCSR creates a new Certificate Signing Request
func CreateCSR(commonName string, organization []string, privateKey *rsa.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: organization,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}
	
	csrPEM := &pem.Block{
		Type:  CSRPEMBlockType,
		Bytes: csrBytes,
	}
	
	var csrBuf bytes.Buffer
	if err := pem.Encode(&csrBuf, csrPEM); err != nil {
		return nil, err
	}
	
	return csrBuf.Bytes(), nil
}

// ParseCSRFromPEM parses a PEM encoded CSR
func ParseCSRFromPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != CSRPEMBlockType {
		return nil, errors.New("failed to parse PEM block containing CSR")
	}
	
	return x509.ParseCertificateRequest(block.Bytes)
}

// CreateSelfSignedCert creates a self-signed certificate
func CreateSelfSignedCert(commonName string, organization []string, privateKey *rsa.PrivateKey, daysValid int) ([]byte, error) {
	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	
	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: organization,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, daysValid),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	
	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	
	// Encode to PEM
	certPEM := &pem.Block{
		Type:  CertificatePEMBlockType,
		Bytes: certBytes,
	}
	
	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, certPEM); err != nil {
		return nil, err
	}
	
	return certBuf.Bytes(), nil
}

// ParseCertFromPEM parses a PEM encoded certificate
func ParseCertFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != CertificatePEMBlockType {
		return nil, errors.New("failed to parse PEM block containing certificate")
	}
	
	return x509.ParseCertificate(block.Bytes)
}

// SignCSRWithCA signs a CSR with a CA certificate
func SignCSRWithCA(csrPEM, caCertPEM, caKeyPEM []byte, daysValid int) ([]byte, error) {
	// Parse CSR
	csr, err := ParseCSRFromPEM(csrPEM)
	if err != nil {
		return nil, err
	}
	
	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR signature verification failed: " + err.Error())
	}
	
	// Parse CA certificate
	caCert, err := ParseCertFromPEM(caCertPEM)
	if err != nil {
		return nil, err
	}
	
	// Parse CA private key
	caKey, err := ParsePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return nil, err
	}
	
	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	
	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, daysValid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	
	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	
	// Encode to PEM
	certPEM := &pem.Block{
		Type:  CertificatePEMBlockType,
		Bytes: certBytes,
	}
	
	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, certPEM); err != nil {
		return nil, err
	}
	
	return certBuf.Bytes(), nil
}