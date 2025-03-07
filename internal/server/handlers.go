package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/yourusername/secure-messaging-poc/internal/binmanager"
)

// handleServerInfo returns server information including the current bin mask
func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	// Extract client certificate info for logging
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		log.Printf("Server info requested by: %s", cert.Subject.CommonName)
	}

	// Prepare response
	info := map[string]interface{}{
		"bin_mask":        fmt.Sprintf("0x%X", s.binManager.GetCurrentMask()),
		"version":         "0.1.0",
		"timestamp":       time.Now().Format(time.RFC3339),
		"message_retention_hours": s.binManager.GetRetentionHours(),
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Verify client has a valid certificate
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return
	}

	cert := r.TLS.PeerCertificates[0]
	certID := cert.SerialNumber.String()

	// Extract certificate info
	certInfo := certmanager.GetCertificateInfo(cert)
	log.Printf("WebSocket connection from certificate: %s", certID)

	// Upgrade connection to WebSocket
	conn, err := s.websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

	// Create client
	client := s.RegisterClient(conn, certInfo)
	defer client.Close()

	// Handle subscription request
	var subscriptionMsg struct {
		Type      string   `json:"type"`
		BinIDs    []uint64 `json:"bin_ids"`
		ClientID  string   `json:"client_id"`
	}

	// Wait for subscription message
	if err := conn.ReadJSON(&subscriptionMsg); err != nil {
		log.Printf("Error reading subscription message: %v", err)
		return
	}

	if subscriptionMsg.Type != "subscribe" {
		log.Printf("Expected subscribe message, got %s", subscriptionMsg.Type)
		return
	}

	// Generate client ID if not provided
	clientID := subscriptionMsg.ClientID
	if clientID == "" {
		clientID = uuid.New().String()
	}

	// Subscribe to bins
	var wg sync.WaitGroup
	for _, binID := range subscriptionMsg.BinIDs {
		binID := binID // Capture for goroutine
		
		// Subscribe to bin
		s.binManager.Subscribe(binID, clientID, client)
		
		// Get recent messages
		recentMessages := s.binManager.GetRecentMessages(binID)
		
		// Send recent messages
		for _, msg := range recentMessages {
			if err := conn.WriteJSON(msg); err != nil {
				log.Printf("Error sending recent message: %v", err)
				return
			}
		}
	}

	// Acknowledge subscription
	ack := map[string]interface{}{
		"type":      "subscribe_ack",
		"client_id": clientID,
		"bin_count": len(subscriptionMsg.BinIDs),
		"timestamp": time.Now().Format(time.RFC3339),
	}
	if err := conn.WriteJSON(ack); err != nil {
		log.Printf("Error sending subscription ack: %v", err)
		return
	}

	// Start a goroutine to handle incoming messages
	go func() {
		for {
			var msg binmanager.Message
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				break
			}

			// Process message
			s.binManager.AddMessage(&msg)
		}

		// Unsubscribe from all bins when connection closes
		for _, binID := range subscriptionMsg.BinIDs {
			s.binManager.Unsubscribe(binID, clientID)
		}
		
		// Close client
		client.Close()
	}()
	
	// Start periodic dummy messages if needed (fixed-size interval)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	// Keep connection alive until closed
	for {
		select {
		case <-ticker.C:
			// Check if connection is still alive
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second)); err != nil {
				log.Printf("Ping error: %v", err)
				return
			}
		}
	}

	// Unsubscribe from all bins when connection closes
	for _, binID := range subscriptionMsg.BinIDs {
		s.binManager.Unsubscribe(binID, clientID)
	}
}

// handleCertificateRequest handles certificate signing requests
func (s *Server) handleCertificateRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify client has a valid certificate for referral
	var referrerID string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		referrerID = cert.SerialNumber.String()
		
		// Check if referrer certificate is revoked
		if s.revocationMgr.IsRevoked(referrerID) {
			http.Error(w, "Referrer certificate is revoked", http.StatusForbidden)
			return
		}
	} else {
		// For bootstrap certificates, no referrer is needed
		// In production, you would have additional authentication here
		referrerID = ""
	}

	// Read request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}

	// Parse CSR
	csr, err := x509.ParseCertificateRequest(body)
	if err != nil {
		http.Error(w, "Invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Sign CSR
	validityDays := 90 // 3 months
	cert, err := s.certAuthority.SignCSR(csr, referrerID, validityDays)
	if err != nil {
		http.Error(w, "Failed to sign CSR: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Register certificate in revocation manager
	certID := cert.SerialNumber.String()
	s.revocationMgr.RegisterCertificate(certID, referrerID)

	// Return the signed certificate
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(cert.Raw)
}

// handleCertificateRevoke handles certificate revocation requests
func (s *Server) handleCertificateRevoke(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify client has a valid certificate
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return
	}

	// Read request body
	var revokeRequest struct {
		CertificateID string `json:"certificate_id"`
		RevokeChildren bool   `json:"revoke_children"`
	}

	if err := json.NewDecoder(r.Body).Decode(&revokeRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get client certificate info
	cert := r.TLS.PeerCertificates[0]
	clientCertID := cert.SerialNumber.String()
	
	// Only allow revocation of self or certificates referred by self
	targetCertID := revokeRequest.CertificateID
	if targetCertID != clientCertID {
		// Check if target was referred by client
		referrerID, err := certmanager.ExtractReferrerID(cert)
		if err != nil || referrerID != clientCertID {
			http.Error(w, "Unauthorized to revoke this certificate", http.StatusForbidden)
			return
		}
	}
	
	// Revoke the certificate
	if revokeRequest.RevokeChildren {
		s.revocationMgr.RevokeWithChildren(targetCertID)
	} else {
		s.revocationMgr.Revoke(targetCertID)
	}
	
	// Return success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"certificate_id": targetCertID,
		"timestamp":      time.Now().Format(time.RFC3339),
	})