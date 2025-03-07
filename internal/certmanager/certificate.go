package certmanager

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	cryptopkg "github.com/yourusername/secure-messaging-poc/pkg/crypto"
)

var (
	// ReferrerOID is the OID used for the referrer extension
	ReferrerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	
	// ErrCertificateRevoked is returned when a certificate is revoked
	ErrCertificateRevoked = errors.New("certificate is revoked")
	
	// ErrReferrerRevoked is returned when a certificate's referrer is revoked
	ErrReferrerRevoked = errors.New("referrer certificate is revoked")
)

// ExtractReferrerID extracts the referrer ID from a certificate
func ExtractReferrerID(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ReferrerOID) {
			return string(ext.Value), nil
		}
	}
	
	return "", errors.New("referrer ID not found")
}

// CreateCSR creates a Certificate Signing Request
func CreateCSR(template *x509.CertificateRequest, key interface{}) ([]byte, error) {
	return x509.CreateCertificateRequest(nil, template, key)
}

// ParseCertificatePEM parses a PEM-encoded certificate
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	return cryptopkg.ParseCertFromPEM(certPEM)
}

// ParseCSRPEM parses a PEM-encoded CSR
func ParseCSRPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	return cryptopkg.ParseCSRFromPEM(csrPEM)
}

// EncodeCertificatePEM encodes a certificate as PEM
func EncodeCertificatePEM(cert *x509.Certificate) ([]byte, error) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// GetCertificateInfo returns basic information about a certificate
func GetCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	info := map[string]interface{}{
		"serial":     cert.SerialNumber.String(),
		"subject":    cert.Subject.CommonName,
		"issuer":     cert.Issuer.CommonName,
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
	}
	
	// Try to extract referrer ID
	if referrerID, err := ExtractReferrerID(cert); err == nil {
		info["referrer_id"] = referrerID
	}
	
	return info
}