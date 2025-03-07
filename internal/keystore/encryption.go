package keystore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/yourusername/secure-messaging-poc/pkg/crypto"
	"golang.org/x/crypto/argon2"
)

// KeyPair holds the encryption and HMAC keys derived from a password
type KeyPair struct {
	EncryptionKey []byte
	HMACKey       []byte
}

// DeriveKeyFromPassword derives encryption and HMAC keys from a password using Argon2id
func DeriveKeyFromPassword(password string, salt []byte) KeyPair {
	// Use Argon2id with recommended parameters
	// Time: 1, Memory: 64MB, Threads: 4, Key Length: 64 bytes (32 for AES, 32 for HMAC)
	derivedKey := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 64)
	
	return KeyPair{
		EncryptionKey: derivedKey[:32], // First 32 bytes for AES-256
		HMACKey:       derivedKey[32:], // Last 32 bytes for HMAC-SHA256
	}
}

// GenerateSalt generates a random salt for key derivation
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// EncryptKey encrypts a key with AES-256-GCM
func EncryptKey(keyData, encryptionKey []byte) (ciphertext, nonce []byte, err error) {
	// Create cipher block
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, err
	}
	
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	
	// Generate nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	
	// Encrypt
	ciphertext = gcm.Seal(nil, nonce, keyData, nil)
	
	return ciphertext, nonce, nil
}

// DecryptKey decrypts a key with AES-256-GCM
func DecryptKey(ciphertext, nonce, encryptionKey []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Check nonce size
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	
	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// CalculateHMAC calculates HMAC-SHA256 of data
func CalculateHMAC(data, hmacKey []byte) []byte {
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256 of data
func VerifyHMAC(data, expectedHMAC, hmacKey []byte) bool {
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	calculatedHMAC := h.Sum(nil)
	return hmac.Equal(calculatedHMAC, expectedHMAC)
}

// EncryptAndAuthenticate encrypts data and calculates HMAC
func EncryptAndAuthenticate(data []byte, keypair KeyPair) (ciphertext, nonce, mac []byte, err error) {
	// Encrypt
	ciphertext, nonce, err = EncryptKey(data, keypair.EncryptionKey)
	if err != nil {
		return nil, nil, nil, err
	}
	
	// Calculate HMAC over ciphertext and nonce
	h := hmac.New(sha256.New, keypair.HMACKey)
	h.Write(ciphertext)
	h.Write(nonce)
	mac = h.Sum(nil)
	
	return ciphertext, nonce, mac, nil
}

// VerifyAndDecrypt verifies HMAC and decrypts data
func VerifyAndDecrypt(ciphertext, nonce, mac []byte, keypair KeyPair) ([]byte, error) {
	// Verify HMAC
	h := hmac.New(sha256.New, keypair.HMACKey)
	h.Write(ciphertext)
	h.Write(nonce)
	expectedMAC := h.Sum(nil)
	
	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("HMAC verification failed")
	}
	
	// Decrypt
	plaintext, err := DecryptKey(ciphertext, nonce, keypair.EncryptionKey)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// EncryptKey encrypts a key with AES-256-GCM
func EncryptKey(keyData, encryptionKey []byte) (ciphertext, nonce []byte, err error) {
	return crypto.AESGCMEncrypt(keyData, encryptionKey)
}

// DecryptKey decrypts a key with AES-256-GCM
func DecryptKey(ciphertext, nonce, encryptionKey []byte) ([]byte, error) {
	return crypto.AESGCMDecrypt(ciphertext, encryptionKey, nonce)
}