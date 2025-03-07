package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

// CertificateAuthority manages the CA operations
type CertificateAuthority struct {
	caCert       *x509.Certificate
	caPrivKey    *rsa.PrivateKey
	organization string
}

// NewCertificateAuthority creates a new certificate authority
func NewCertificateAuthority(certPath, keyPath, organization string) (*CertificateAuthority, error) {
	ca := &CertificateAuthority{
		organization: organization,
	}
	
	// Check if the CA certificate and key exist
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		// Create new CA certificate and key
		cert, key, err := ca.generateCA(organization)
		if err != nil {
			return nil, err
		}
		
		// Save to files
		if err := ca.saveCertAndKey(cert, key, certPath, keyPath); err != nil {
			return nil, err
		}
		
		ca.caCert = cert
		ca.caPrivKey = key
	} else {
		// Load existing CA certificate and key
		cert, key, err := ca.loadCertAndKey(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		
		ca.caCert = cert
		ca.caPrivKey = key
	}
	
	return ca, nil
}

// GetCACertificate returns the CA certificate
func (ca *CertificateAuthority) GetCACertificate() (*x509.Certificate, error) {
	if ca.caCert == nil {
		return nil, errors.New("CA certificate not initialized")
	}
	return ca.caCert, nil
}

// SignCSR signs a certificate signing request
func (ca *CertificateAuthority) SignCSR(csr *x509.CertificateRequest, referrerID string, validityDays int) (*x509.Certificate, error) {
	if ca.caCert == nil || ca.caPrivKey == nil {
		return nil, errors.New("CA not initialized")
	}
	
	// Validate CSR
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("invalid CSR signature")
	}
	
	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	
	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validityDays)
	
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   csr.Subject.CommonName,
			Organization: []string{ca.organization},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	
	// Add referrer extension if provided
	if referrerID != "" {
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:       ReferrerOID,
				Critical: false,
				Value:    []byte(referrerID),
			},
		}
	}
	
	// Sign the certificate
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.caCert,
		csr.PublicKey,
		ca.caPrivKey,
	)
	if err != nil {
		return nil, err
	}
	
	// Parse the signed certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	
	return cert, nil
}

// generateCA generates a new CA certificate and private key
func (ca *CertificateAuthority) generateCA(organization string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate a new private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	
	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Secure Messaging CA",
			Organization: []string{organization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	
	// Self-sign the certificate
	caCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&caPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		return nil, nil, err
	}
	
	// Parse the certificate
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, err
	}
	
	return caCert, caPrivKey, nil
}

// saveCertAndKey saves the certificate and private key to files
func (ca *CertificateAuthority) saveCertAndKey(cert *x509.Certificate, key *rsa.PrivateKey, certPath, keyPath string) error {
	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	
	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return err
	}
	
	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	
	err = pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err
	}
	
	return nil
}

// loadCertAndKey loads the certificate and private key from files
func (ca *CertificateAuthority) loadCertAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("failed to parse certificate PEM")
	}
	
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	
	// Load private key
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("failed to parse key PEM")
	}
	
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	
	return cert, key, nil
}