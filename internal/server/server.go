package server

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yourusername/secure-messaging-poc/internal/binmanager"
	"github.com/yourusername/secure-messaging-poc/internal/certmanager"
	"github.com/yourusername/secure-messaging-poc/internal/keystore"
)

// Server represents the messaging server
type Server struct {
	address        string
	tlsConfig      *tls.Config
	binManager     *binmanager.BinManager
	revocationMgr  *certmanager.RevocationManager
	certAuthority  *certmanager.CertificateAuthority
	keyStore       *keystore.EncryptedKeyStore
	httpServer     *http.Server
	websocketUpgrader *websocket.Upgrader
}

// NewServer creates a new server instance
func NewServer(
	address string,
	tlsConfig *tls.Config,
	binManager *binmanager.BinManager,
	revocationMgr *certmanager.RevocationManager,
	certAuthority *certmanager.CertificateAuthority,
	keyStore *keystore.EncryptedKeyStore,
) *Server {
	server := &Server{
		address:        address,
		tlsConfig:      tlsConfig,
		binManager:     binManager,
		revocationMgr:  revocationMgr,
		certAuthority:  certAuthority,
		keyStore:       keyStore,
		websocketUpgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// In production, you'd want to restrict this
				return true
			},
		},
	}
	
	// Setup HTTP router
	mux := http.NewServeMux()
	
	// WebSocket endpoint for message streaming
	mux.HandleFunc("/ws", server.handleWebSocket)
	
	// Certificate management endpoints
	mux.HandleFunc("/api/certificate/request", server.handleCertificateRequest)
	mux.HandleFunc("/api/certificate/revoke", server.handleCertificateRevoke)
	
	// Key storage endpoints
	mux.HandleFunc("/api/key/store", server.handleKeyStore)
	mux.HandleFunc("/api/key/retrieve", server.handleKeyRetrieve)
	
	// Server info endpoint
	mux.HandleFunc("/api/info", server.handleServerInfo)
	
	// Health check endpoint
	mux.HandleFunc("/health", server.handleHealth)
	
	// Create HTTP server
	server.httpServer = &http.Server{
		Addr:      address,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	
	return server
}

// Start starts the server
func (s *Server) Start() error {
	log.Printf("Starting server on %s", s.address)
	
	// Start with TLS
	return s.httpServer.ListenAndServeTLS("", "")
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// GetCurrentBinMask returns the current bin mask
func (s *Server) GetCurrentBinMask() uint64 {
	return s.binManager.GetCurrentMask()
}

// RegisterClient registers a client connection with certificate information
func (s *Server) RegisterClient(conn *websocket.Conn, certInfo map[string]interface{}) *Client {
	client := NewClient(conn, certInfo)
	
	// Extract certificate ID and referrer ID
	certID, _ := certInfo["serial"].(string)
	referrerID, _ := certInfo["referrer_id"].(string)
	
	// Register certificate in revocation manager
	if certID != "" && referrerID != "" {
		s.revocationMgr.RegisterCertificate(certID, referrerID)
	}
	
	return client
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// handleServerInfo returns server information including the current bin mask
func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	// Implementation details in handlers.go
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Implementation details in handlers.go
}

// handleCertificateRequest handles certificate signing requests
func (s *Server) handleCertificateRequest(w http.ResponseWriter, r *http.Request) {
	// Implementation details in handlers.go
}

// handleCertificateRevoke handles certificate revocation requests
func (s *Server) handleCertificateRevoke(w http.ResponseWriter, r *http.Request) {
	// Implementation details in handlers.go
}

// handleKeyStore handles encrypted key storage requests
func (s *Server) handleKeyStore(w http.ResponseWriter, r *http.Request) {
	// Implementation details in handlers.go
}

// handleKeyRetrieve handles encrypted key retrieval requests
func (s *Server) handleKeyRetrieve(w http.ResponseWriter, r *http.Request) {
	// Implementation details in handlers.go
}