package keystore

import (
	"errors"
	"sync"
	"time"
)

// EncryptedKeyData represents an encrypted key
type EncryptedKeyData struct {
	CertID       string
	EncryptedKey []byte
	IV           []byte
	HMAC         []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// EncryptedKeyStore manages encrypted keys
type EncryptedKeyStore struct {
	store map[string]EncryptedKeyData
	mu    sync.RWMutex
}

// NewEncryptedKeyStore creates a new encrypted key store
func NewEncryptedKeyStore() *EncryptedKeyStore {
	return &EncryptedKeyStore{
		store: make(map[string]EncryptedKeyData),
	}
}

// StoreKey stores an encrypted key
func (eks *EncryptedKeyStore) StoreKey(certID string, encryptedKey, iv, hmac []byte) error {
	if certID == "" {
		return errors.New("certificate ID cannot be empty")
	}
	
	now := time.Now()
	
	eks.mu.Lock()
	defer eks.mu.Unlock()
	
	// Check if key already exists
	existing, exists := eks.store[certID]
	if exists {
		// Update existing key
		existing.EncryptedKey = encryptedKey
		existing.IV = iv
		existing.HMAC = hmac
		existing.UpdatedAt = now
		eks.store[certID] = existing
	} else {
		// Create new key
		eks.store[certID] = EncryptedKeyData{
			CertID:       certID,
			EncryptedKey: encryptedKey,
			IV:           iv,
			HMAC:         hmac,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
	}
	
	return nil
}

// GetKey retrieves an encrypted key
func (eks *EncryptedKeyStore) GetKey(certID string) (EncryptedKeyData, error) {
	eks.mu.RLock()
	defer eks.mu.RUnlock()
	
	keyData, exists := eks.store[certID]
	if !exists {
		return EncryptedKeyData{}, errors.New("key not found for certificate ID")
	}
	
	return keyData, nil
}

// DeleteKey deletes an encrypted key
func (eks *EncryptedKeyStore) DeleteKey(certID string) error {
	eks.mu.Lock()
	defer eks.mu.Unlock()
	
	if _, exists := eks.store[certID]; !exists {
		return errors.New("key not found for certificate ID")
	}
	
	delete(eks.store, certID)
	return nil
}

// ListKeys returns a list of all certificate IDs with stored keys
func (eks *EncryptedKeyStore) ListKeys() []string {
	eks.mu.RLock()
	defer eks.mu.RUnlock()
	
	keys := make([]string, 0, len(eks.store))
	for certID := range eks.store {
		keys = append(keys, certID)
	}
	
	return keys
}