package crypto

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestGenerateRSAKey(t *testing.T) {
	// Test different key sizes
	keySizes := []int{1024, 2048, 3072, 4096}

	for _, size := range keySizes {
		t.Run("Key size: "+string(rune(size)), func(t *testing.T) {
			key, err := GenerateRSAKey(size)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}

			// Check key is not nil
			if key == nil {
				t.Fatal("Generated key is nil")
			}

			// Check key size
			if key.N.BitLen() != size {
				t.Errorf("Key size mismatch: got %d, want %d", key.N.BitLen(), size)
			}

			// Verify key can be used for encryption/decryption (private key test)
			// This is a simple sanity check that key operations work
			if !key.Validate() {
				t.Error("Key validation failed")
			}
		})
	}
}

func TestMarshalAndParsePrivateKey(t *testing.T) {
	// Generate a key
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal key to PEM
	pemData, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Check that the PEM data contains the expected header
	if !bytes.Contains(pemData, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Error("PEM data does not contain RSA PRIVATE KEY header")
	}

	// Parse the PEM data back to a key
	parsedKey, err := ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to parse PEM private key: %v", err)
	}

	// Check that the parsed key matches the original
	if parsedKey.N.Cmp(key.N) != 0 { // Compare modulus as a simple equality check
		t.Error("Parsed key does not match original key")
	}

	// Test parsing with invalid PEM data
	_, err = ParsePrivateKeyFromPEM([]byte("invalid PEM data"))
	if err == nil {
		t.Error("Parsing invalid PEM data should fail")
	}
}

func TestCreateAndParseCSR(t *testing.T) {
	// Generate a key
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a CSR
	commonName := "test.example.com"
	organization := []string{"Test Organization"}
	
	csrPEM, err := CreateCSR(commonName, organization, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Parse the CSR
	csr, err := ParseCSRFromPEM(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Verify CSR fields
	if csr.Subject.CommonName != commonName {
		t.Errorf("CSR common name mismatch: got %s, want %s", csr.Subject.CommonName, commonName)
	}

	if len(csr.Subject.Organization) != len(organization) || csr.Subject.Organization[0] != organization[0] {
		t.Errorf("CSR organization mismatch: got %v, want %v", csr.Subject.Organization, organization)
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}

	// Test parsing with invalid CSR
	_, err = ParseCSRFromPEM([]byte("invalid CSR PEM data"))
	if err == nil {
		t.Error("Parsing invalid CSR PEM data should fail")
	}
}

func TestCreateSelfSignedCert(t *testing.T) {
	// Generate a key
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a self-signed certificate
	commonName := "test.example.com"
	organization := []string{"Test Organization"}
	validDays := 30
	
	certPEM, err := CreateSelfSignedCert(commonName, organization, key, validDays)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	// Parse the certificate
	cert, err := ParseCertFromPEM(certPEM)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify certificate fields
	if cert.Subject.CommonName != commonName {
		t.Errorf("Certificate common name mismatch: got %s, want %s", cert.Subject.CommonName, commonName)
	}

	if len(cert.Subject.Organization) != len(organization) || cert.Subject.Organization[0] != organization[0] {
		t.Errorf("Certificate organization mismatch: got %v, want %v", cert.Subject.Organization, organization)
	}

	// Check validity period
	now := time.Now()
	expectedExpiry := now.AddDate(0, 0, validDays)
	if cert.NotBefore.After(now) {
		t.Errorf("Certificate not valid yet: not before %v, current time %v", cert.NotBefore, now)
	}
	
	// Allow for a small time difference in test execution
	dateDiff := cert.NotAfter.Sub(expectedExpiry)
	if dateDiff < -time.Minute || dateDiff > time.Minute {
		t.Errorf("Certificate expiry date mismatch: got %v, want approximately %v", cert.NotAfter, expectedExpiry)
	}

	// Verify that the certificate is self-signed
	if cert.Issuer.CommonName != cert.Subject.CommonName {
		t.Errorf("Certificate issuer CN (%s) should match subject CN (%s) for self-signed cert", 
		         cert.Issuer.CommonName, cert.Subject.CommonName)
	}

	// Verify certificate can be used for server auth
	hasServerAuthExtKeyUsage := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuthExtKeyUsage = true
			break
		}
	}
	if !hasServerAuthExtKeyUsage {
		t.Error("Certificate is missing ExtKeyUsageServerAuth")
	}

	// Verify certificate chain
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	_, err = cert.Verify(opts)
	if err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestSignCSRWithCA(t *testing.T) {
	// Generate CA key and cert
	caKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate CA RSA key: %v", err)
	}

	caCertPEM, err := CreateSelfSignedCert("CA Example", []string{"CA Org"}, caKey, 365)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caKeyPEM, err := MarshalPrivateKeyToPEM(caKey)
	if err != nil {
		t.Fatalf("Failed to marshal CA private key: %v", err)
	}

	// Generate client key and CSR
	clientKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate client RSA key: %v", err)
	}

	clientCSRPEM, err := CreateCSR("client.example.com", []string{"Client Org"}, clientKey)
	if err != nil {
		t.Fatalf("Failed to create client CSR: %v", err)
	}

	// Sign the CSR with the CA
	clientCertPEM, err := SignCSRWithCA(clientCSRPEM, caCertPEM, caKeyPEM, 30)
	if err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}

	// Parse the client certificate
	clientCert, err := ParseCertFromPEM(clientCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	// Parse the CA certificate
	caCert, err := ParseCertFromPEM(caCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Verify certificate fields
	if clientCert.Subject.CommonName != "client.example.com" {
		t.Errorf("Client cert common name mismatch: got %s, want %s", 
		         clientCert.Subject.CommonName, "client.example.com")
	}

	// Verify the certificate was issued by our CA
	if clientCert.Issuer.CommonName != caCert.Subject.CommonName {
		t.Errorf("Client cert issuer CN (%s) should match CA subject CN (%s)", 
		         clientCert.Issuer.CommonName, caCert.Subject.CommonName)
	}

	// Verify certificate chain
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	_, err = clientCert.Verify(opts)
	if err != nil {
		t.Errorf("Client certificate verification failed: %v", err)
	}
	
	// Test with invalid CSR
	_, err = SignCSRWithCA([]byte("invalid CSR"), caCertPEM, caKeyPEM, 30)
	if err == nil {
		t.Error("Signing with invalid CSR should fail")
	} else if !strings.Contains(err.Error(), "failed to parse PEM block") {
		t.Errorf("Unexpected error message for invalid CSR: %v", err)
	}
}