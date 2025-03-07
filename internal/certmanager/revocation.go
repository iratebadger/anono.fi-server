package certmanager

import (
	"sync"
	"time"
)

// RevocationManager handles certificate revocation
type RevocationManager struct {
	revokedCerts    map[string]time.Time // certificate ID -> revocation time
	referrerMapping map[string][]string  // referrerID -> []childIDs
	mu              sync.RWMutex
}

// NewRevocationManager creates a new revocation manager
func NewRevocationManager() *RevocationManager {
	return &RevocationManager{
		revokedCerts:    make(map[string]time.Time),
		referrerMapping: make(map[string][]string),
	}
}

// RegisterCertificate registers a new certificate with its referrer
func (rm *RevocationManager) RegisterCertificate(certID, referrerID string) {
	if referrerID == "" {
		return // No referrer to register
	}
	
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// Add to referrer mapping
	if _, exists := rm.referrerMapping[referrerID]; !exists {
		rm.referrerMapping[referrerID] = make([]string, 0)
	}
	
	rm.referrerMapping[referrerID] = append(rm.referrerMapping[referrerID], certID)
}

// Revoke marks a certificate as revoked
func (rm *RevocationManager) Revoke(certID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.revokedCerts[certID] = time.Now()
}

// RevokeWithChildren revokes a certificate and all its descendants
func (rm *RevocationManager) RevokeWithChildren(certID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// Helper function for recursive revocation
	var revokeRecursive func(string)
	revokeRecursive = func(id string) {
		// Mark as revoked
		rm.revokedCerts[id] = time.Now()
		
		// Revoke all children
		if children, ok := rm.referrerMapping[id]; ok {
			for _, childID := range children {
				revokeRecursive(childID)
			}
		}
	}
	
	revokeRecursive(certID)
}

// IsRevoked checks if a certificate is revoked
func (rm *RevocationManager) IsRevoked(certID string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	_, revoked := rm.revokedCerts[certID]
	return revoked
}

// GetRevokedCertificates returns all revoked certificates
func (rm *RevocationManager) GetRevokedCertificates() map[string]time.Time {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// Return a copy to avoid concurrent map access
	result := make(map[string]time.Time)
	for id, time := range rm.revokedCerts {
		result[id] = time
	}
	
	return result
}

// GetChildCount returns the number of child certificates for a given referrer
func (rm *RevocationManager) GetChildCount(referrerID string) int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	if children, ok := rm.referrerMapping[referrerID]; ok {
		return len(children)
	}
	
	return 0
}