package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/secure-messaging-poc/internal/binmanager"
	"github.com/yourusername/secure-messaging-poc/internal/certmanager"
	"github.com/yourusername/secure-messaging-poc/internal/config"
	"github.com/yourusername/secure-messaging-poc/internal/keystore"
	"github.com/yourusername/secure-messaging-poc/internal/server"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize certificate authority
	ca, err := certmanager.NewCertificateAuthority(
		cfg.CA.CertPath,
		cfg.CA.KeyPath,
		cfg.CA.Organization,
	)
	if err != nil {
		log.Fatalf("Failed to initialize certificate authority: %v", err)
	}

	// Initialize revocation manager
	revocationMgr := certmanager.NewRevocationManager()

	// Initialize bin manager with power-of-2 bin masking
	binMgr := binmanager.NewBinManager(
		cfg.BinManager.InitialMask,
		cfg.BinManager.MessageRetention,
	)

	// Initialize key store
	keyStore := keystore.NewEncryptedKeyStore()

	// Setup TLS config for client certificate authentication
	tlsConfig, err := setupTLSConfig(ca, revocationMgr)
	if err != nil {
		log.Fatalf("Failed to setup TLS config: %v", err)
	}

	// Initialize server
	srv := server.NewServer(
		cfg.Server.Address,
		tlsConfig,
		binMgr,
		revocationMgr,
		ca,
		keyStore,
	)

	// Start message cleanup service
	binMgr.StartCleanupService(time.Minute)

	// Start the server
	log.Printf("Starting secure messaging server on %s", cfg.Server.Address)
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited properly")
}

func setupTLSConfig(ca *certmanager.CertificateAuthority, rm *certmanager.RevocationManager) (*tls.Config, error) {
	// Load CA certificate
	caCert, err := ca.GetCACertificate()
	if err != nil {
		return nil, err
	}

	// Create certificate pool with our CA
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Custom verification including revocation check
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return nil // Standard verification already failed
			}
			
			cert := verifiedChains[0][0]
			certID := cert.SerialNumber.String()
			
			// Check if certificate is revoked
			if rm.IsRevoked(certID) {
				return certmanager.ErrCertificateRevoked
			}
			
			// Check if referrer is revoked
			referrerID, err := certmanager.ExtractReferrerID(cert)
			if err == nil && referrerID != "" && rm.IsRevoked(referrerID) {
				return certmanager.ErrReferrerRevoked
			}
			
			return nil
		},
	}, nil
}