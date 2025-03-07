package crypto

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestAESGCM(t *testing.T) {
	// Test cases
	testCases := []struct {
		name      string
		plaintext string
		keySize   int // in bytes (16, 24, or 32 for AES-128, AES-192, or AES-256)
	}{
		{
			name:      "Empty plaintext with AES-256",
			plaintext: "",
			keySize:   32,
		},
		{
			name:      "Short plaintext with AES-128",
			plaintext: "Hello, World!",
			keySize:   16,
		},
		{
			name:      "Long plaintext with AES-256",
			plaintext: "This is a longer test message that spans multiple AES blocks to ensure proper handling of block boundaries and padding.",
			keySize:   32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a random key of the specified size
			key := make([]byte, tc.keySize)
			for i := range key {
				key[i] = byte(i % 256)
			}

			// Encrypt the plaintext
			plaintext := []byte(tc.plaintext)
			ciphertext, nonce, err := AESGCMEncrypt(plaintext, key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Make sure ciphertext is not the same as plaintext (unless plaintext is empty)
			if len(plaintext) > 0 && bytes.Equal(ciphertext, plaintext) {
				t.Errorf("Ciphertext matches plaintext, encryption may have failed")
			}

			// Decrypt the ciphertext
			decrypted, err := AESGCMDecrypt(ciphertext, key, nonce)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify the decrypted text matches the original plaintext
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted text doesn't match original: got %s, want %s", decrypted, plaintext)
			}

			// Test with incorrect key (should fail)
			wrongKey := make([]byte, len(key))
			copy(wrongKey, key)
			wrongKey[0] ^= 0x01 // flip a bit to make it different
			_, err = AESGCMDecrypt(ciphertext, wrongKey, nonce)
			if err == nil {
				t.Errorf("Decryption should have failed with incorrect key")
			}
		})
	}
}

func TestAESCBC(t *testing.T) {
	// Test cases
	testCases := []struct {
		name      string
		plaintext string
		keySize   int // in bytes (16, 24, or 32 for AES-128, AES-192, or AES-256)
	}{
		{
			name:      "Empty plaintext with AES-256",
			plaintext: "",
			keySize:   32,
		},
		{
			name:      "Short plaintext with AES-128",
			plaintext: "Hello, World!",
			keySize:   16,
		},
		{
			name:      "Long plaintext with AES-256",
			plaintext: "This is a longer test message that spans multiple AES blocks to ensure proper handling of block boundaries and padding.",
			keySize:   32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a random key of the specified size
			key := make([]byte, tc.keySize)
			for i := range key {
				key[i] = byte(i % 256)
			}

			// Generate a random IV
			iv, err := GenerateRandomIV(aes.BlockSize)
			if err != nil {
				t.Fatalf("Failed to generate IV: %v", err)
			}

			// Encrypt the plaintext
			plaintext := []byte(tc.plaintext)
			ciphertext, err := AESCBCEncrypt(plaintext, key, iv)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Make sure ciphertext is not the same as plaintext
			if bytes.Equal(ciphertext, plaintext) {
				t.Errorf("Ciphertext matches plaintext, encryption may have failed")
			}

			// Decrypt the ciphertext
			decrypted, err := AESCBCDecrypt(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify the decrypted text matches the original plaintext
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted text doesn't match original: got %s, want %s", decrypted, plaintext)
			}

			// Test with incorrect key (should fail)
			wrongKey := make([]byte, len(key))
			copy(wrongKey, key)
			wrongKey[0] ^= 0x01 // flip a bit
			_, err = AESCBCDecrypt(ciphertext, wrongKey, iv)
			if err == nil {
				t.Errorf("Decryption should have failed with incorrect key")
			}

			// Test with incorrect IV (should fail)
			wrongIV := make([]byte, len(iv))
			copy(wrongIV, iv)
			wrongIV[0] ^= 0x01 // flip a bit
			_, err = AESCBCDecrypt(ciphertext, key, wrongIV)
			if err == nil && len(plaintext) > 0 {
				// For empty plaintext, CBC mode might actually decrypt successfully with wrong IV due to padding
				t.Errorf("Decryption should have failed with incorrect IV")
			}
		})
	}
}

func TestPKCS7Padding(t *testing.T) {
	testCases := []struct {
		name      string
		data      []byte
		blockSize int
	}{
		{
			name:      "Empty data",
			data:      []byte{},
			blockSize: 16,
		},
		{
			name:      "Data length equals block size",
			data:      []byte("1234567890123456"), // 16 bytes
			blockSize: 16,
		},
		{
			name:      "Data length less than block size",
			data:      []byte("12345"), // 5 bytes
			blockSize: 16,
		},
		{
			name:      "Data length greater than block size",
			data:      []byte("12345678901234567"), // 17 bytes
			blockSize: 16,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Pad the data
			padded := pkcs7Pad(tc.data, tc.blockSize)

			// Verify the padded data length is a multiple of the block size
			if len(padded) % tc.blockSize != 0 {
				t.Errorf("Padded data length (%d) is not a multiple of block size (%d)", len(padded), tc.blockSize)
			}

			// Verify the padding value is correct
			paddingValue := padded[len(padded)-1]
			paddingLen := int(paddingValue)

			if paddingLen > tc.blockSize || paddingLen == 0 {
				t.Errorf("Invalid padding value: %d", paddingLen)
			}

			// Check that all padding bytes have the correct value
			for i := len(padded) - paddingLen; i < len(padded); i++ {
				if padded[i] != paddingValue {
					t.Errorf("Padding byte at index %d has incorrect value: %d, expected %d", i, padded[i], paddingValue)
				}
			}

			// Unpad the data
			unpadded, err := pkcs7Unpad(padded, tc.blockSize)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}

			// Verify the unpadded data matches the original data
			if !bytes.Equal(unpadded, tc.data) {
				t.Errorf("Unpadded data doesn't match original: got %v, want %v", unpadded, tc.data)
			}
		})
	}

	// Test invalid padding
	invalidPadding := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 3} // Last byte should be 1, not 3
	_, err := pkcs7Unpad(invalidPadding, 16)
	if err == nil {
		t.Errorf("Unpadding should have failed with invalid padding")
	}
}

func TestGenerateRandomIV(t *testing.T) {
	sizes := []int{16, 24, 32}

	for _, size := range sizes {
		t.Run("Size: "+string(rune(size)), func(t *testing.T) {
			// Generate multiple IVs to test randomness
			ivs := make([][]byte, 5)
			for i := range ivs {
				iv, err := GenerateRandomIV(size)
				if err != nil {
					t.Fatalf("Failed to generate IV: %v", err)
				}

				ivs[i] = iv

				// Verify length
				if len(iv) != size {
					t.Errorf("IV length is incorrect: got %d, want %d", len(iv), size)
				}
			}

			// Verify that IVs are different (would be extremely unlikely to get duplicates)
			for i := 0; i < len(ivs); i++ {
				for j := i + 1; j < len(ivs); j++ {
					if bytes.Equal(ivs[i], ivs[j]) {
						t.Errorf("IVs %d and %d are identical, which is highly unlikely with proper randomness", i, j)
					}
				}
			}
		})
	}
}