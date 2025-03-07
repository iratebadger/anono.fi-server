package keystore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/yourusername/secure-messaging-poc/pkg/crypto"
)

func TestKeyDerivation(t *testing.T) {
	// Test with different passwords and salts
	testCases := []struct {
		name     string
		password string
		salt     []byte
	}{
		{
			name:     "Simple password with random salt",
			password: "simple-password",
			salt:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
		{
			name:     "Complex password with random salt",
			password: "Complex_P@ssw0rd!123",
			salt:     []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		},
		{
			name:     "Empty password with random salt",
			password: "",
			salt:     []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Derive keys
			keyPair := DeriveKeyFromPassword(tc.password, tc.salt)
			
			// Check key lengths
			if len(keyPair.EncryptionKey) != 32 {
				t.Errorf("Encryption key length incorrect: got %d, want 32", len(keyPair.EncryptionKey))
			}
			
			if len(keyPair.HMACKey) != 32 {
				t.Errorf("HMAC key length incorrect: got %d, want 32", len(keyPair.HMACKey))
			}
			
			// Check that deriving keys again with the same password and salt gives the same result
			keyPair2 := DeriveKeyFromPassword(tc.password, tc.salt)
			
			if !bytes.Equal(keyPair.EncryptionKey, keyPair2.EncryptionKey) {
				t.Error("Encryption keys don't match for the same password and salt")
			}
			
			if !bytes.Equal(keyPair.HMACKey, keyPair2.HMACKey) {
				t.Error("HMAC keys don't match for the same password and salt")
			}
			
			// Check that different passwords give different keys
			differentKeyPair := DeriveKeyFromPassword(tc.password+"different", tc.salt)
			
			if bytes.Equal(keyPair.EncryptionKey, differentKeyPair.EncryptionKey) {
				t.Error("Encryption keys should be different for different passwords")
			}
			
			if bytes.Equal(keyPair.HMACKey, differentKeyPair.HMACKey) {
				t.Error("HMAC keys should be different for different passwords")
			}
			
			// Check that different salts give different keys
			differentSalt := make([]byte, len(tc.salt))
			copy(differentSalt, tc.salt)
			differentSalt[0] ^= 0x01 // Flip a bit
			
			differentSaltKeyPair := DeriveKeyFromPassword(tc.password, differentSalt)
			
			if bytes.Equal(keyPair.EncryptionKey, differentSaltKeyPair.EncryptionKey) {
				t.Error("Encryption keys should be different for different salts")
			}
			
			if bytes.Equal(keyPair.HMACKey, differentSaltKeyPair.HMACKey) {
				t.Error("HMAC keys should be different for different salts")
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	// Generate multiple salts to test randomness
	salts := make([][]byte, 5)
	
	for i := range salts {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("Failed to generate salt: %v", err)
		}
		
		salts[i] = salt
		
		// Check length
		if len(salt) != 16 {
			t.Errorf("Salt length incorrect: got %d, want 16", len(salt))
		}
	}
	
	// Verify that salts are different (would be extremely unlikely to get duplicates)
	for i := 0; i < len(salts); i++ {
		for j := i + 1; j < len(salts); j++ {
			if bytes.Equal(salts[i], salts[j]) {
				t.Errorf("Salts %d and %d are identical, which is highly unlikely with proper randomness", i, j)
			}
		}
	}
}

func TestCalculateAndVerifyHMAC(t *testing.T) {
	// Test data
	data := []byte("test data for HMAC calculation")
	key := []byte("hmac key")
	
	// Calculate HMAC
	mac := CalculateHMAC(data, key)
	
	// Verify HMAC is correct length
	if len(mac) != sha256.Size {
		t.Errorf("HMAC length incorrect: got %d, want %d", len(mac), sha256.Size)
	}
	
	// Verify HMAC manually
	h := hmac.New(sha256.New, key)
	h.Write(data)
	expectedMAC := h.Sum(nil)
	
	if !bytes.Equal(mac, expectedMAC) {
		t.Error("Calculated HMAC doesn't match expected value")
	}
	
	// Verify using VerifyHMAC
	if !VerifyHMAC(data, mac, key) {
		t.Error("HMAC verification failed for valid data and MAC")
	}
	
	// Test with modified data
	modifiedData := make([]byte, len(data))
	copy(modifiedData, data)
	modifiedData[0] ^= 0x01 // Flip a bit
	
	if VerifyHMAC(modifiedData, mac, key) {
		t.Error("HMAC verification should fail for modified data")
	}
	
	// Test with modified MAC
	modifiedMAC := make([]byte, len(mac))
	copy(modifiedMAC, mac)
	modifiedMAC[0] ^= 0x01 // Flip a bit
	
	if VerifyHMAC(data, modifiedMAC, key) {
		t.Error("HMAC verification should fail for modified MAC")
	}
	
	// Test with modified key
	modifiedKey := make([]byte, len(key))
	copy(modifiedKey, key)
	modifiedKey[0] ^= 0x01 // Flip a bit
	
	if VerifyHMAC(data, mac, modifiedKey) {
		t.Error("HMAC verification should fail for modified key")
	}
}

func TestEncryptAndAuthenticate(t *testing.T) {
	// Test data
	data := []byte("sensitive data to be encrypted and authenticated")
	password := "test-password"
	salt, _ := GenerateSalt()
	
	// Derive key pair
	keyPair := DeriveKeyFromPassword(password, salt)
	
	// Encrypt and authenticate
	ciphertext, nonce, mac, err := EncryptAndAuthenticate(data, keyPair)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Check that ciphertext is not the same as plaintext
	if bytes.Equal(ciphertext, data) {
		t.Error("Ciphertext should be different from plaintext")
	}
	
	// Verify the MAC is correct
	h := hmac.New(sha256.New, keyPair.HMACKey)
	h.Write(ciphertext)
	h.Write(nonce)
	expectedMAC := h.Sum(nil)
	
	if !bytes.Equal(mac, expectedMAC) {
		t.Error("MAC doesn't match expected value")
	}
	
	// Decrypt and verify
	plaintext, err := VerifyAndDecrypt(ciphertext, nonce, mac, keyPair)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	// Check that decrypted plaintext matches original data
	if !bytes.Equal(plaintext, data) {
		t.Error("Decrypted plaintext doesn't match original data")
	}
	
	// Test with modified ciphertext
	modifiedCiphertext := make([]byte, len(ciphertext))
	copy(modifiedCiphertext, ciphertext)
	modifiedCiphertext[0] ^= 0x01 // Flip a bit
	
	_, err = VerifyAndDecrypt(modifiedCiphertext, nonce, mac, keyPair)
	if err == nil {
		t.Error("Verification should fail for modified ciphertext")
	}
	
	// Test with modified nonce
	modifiedNonce := make([]byte, len(nonce))
	copy(modifiedNonce, nonce)
	modifiedNonce[0] ^= 0x01 // Flip a bit
	
	_, err = VerifyAndDecrypt(ciphertext, modifiedNonce, mac, keyPair)
	if err == nil {
		t.Error("Verification should fail for modified nonce")
	}
	
	// Test with modified MAC
	modifiedMAC := make([]byte, len(mac))
	copy(modifiedMAC, mac)
	modifiedMAC[0] ^= 0x01 // Flip a bit
	
	_, err = VerifyAndDecrypt(ciphertext, nonce, modifiedMAC, keyPair)
	if err == nil {
		t.Error("Verification should fail for modified MAC")
	}
	
	// Test with derived keys from wrong password
	wrongKeyPair := DeriveKeyFromPassword("wrong-password", salt)
	_, err = VerifyAndDecrypt(ciphertext, nonce, mac, wrongKeyPair)
	if err == nil {
		t.Error("Verification should fail with wrong key")
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	// Test data
	keyData := []byte("sensitive key data to be encrypted")
	encryptionKey := make([]byte, 32)
	for i := range encryptionKey {
		encryptionKey[i] = byte(i)
	}
	
	// Encrypt the key
	ciphertext, nonce, err := crypto.AESGCMEncrypt(keyData, encryptionKey)
	if err != nil {
		t.Fatalf("Key encryption failed: %v", err)
	}
	
	// Decrypt the key
	plaintext, err := crypto.AESGCMDecrypt(ciphertext, encryptionKey, nonce)
	if err != nil {
		t.Fatalf("Key decryption failed: %v", err)
	}
	
	// Check that decrypted plaintext matches original data
	if !bytes.Equal(plaintext, keyData) {
		t.Error("Decrypted key doesn't match original data")
	}
	
	// Test decryption with wrong key
	wrongKey := make([]byte, len(encryptionKey))
	copy(wrongKey, encryptionKey)
	wrongKey[0] ^= 0x01 // Flip a bit
	
	_, err = crypto.AESGCMDecrypt(ciphertext, wrongKey, nonce)
	if err == nil {
		t.Error("Decryption should fail with wrong key")
	}
}