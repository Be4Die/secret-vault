package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"secret-vault/internal/infrastructure/crypto"
)

func validKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestAESEncryptor_Roundtrip(t *testing.T) {
	enc := crypto.NewAESEncryptor()
	key := validKey(t)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"empty", []byte("")},
		{"single byte", []byte("x")},
		{"binary data", []byte{0x00, 0xFF, 0x80, 0x01}},
		{"unicode", []byte("привет мир 🔑")},
		{"large payload", bytes.Repeat([]byte("a"), 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			if bytes.Equal(ciphertext, tt.plaintext) && len(tt.plaintext) > 0 {
				t.Error("ciphertext should differ from plaintext")
			}

			decrypted, err := enc.Decrypt(ciphertext, key)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestAESEncryptor_DifferentNonce(t *testing.T) {
	enc := crypto.NewAESEncryptor()
	key := validKey(t)
	plaintext := []byte("same data")

	c1, _ := enc.Encrypt(plaintext, key)
	c2, _ := enc.Encrypt(plaintext, key)

	if bytes.Equal(c1, c2) {
		t.Error("two encryptions of same data should produce different ciphertexts (random nonce)")
	}
}

func TestAESEncryptor_WrongKey(t *testing.T) {
	enc := crypto.NewAESEncryptor()
	key1 := validKey(t)
	key2 := validKey(t)

	ciphertext, err := enc.Encrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = enc.Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestAESEncryptor_InvalidKeySize(t *testing.T) {
	enc := crypto.NewAESEncryptor()

	_, err := enc.Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Error("encrypt with invalid key size should fail")
	}
}

func TestAESEncryptor_TamperedCiphertext(t *testing.T) {
	enc := crypto.NewAESEncryptor()
	key := validKey(t)

	ciphertext, _ := enc.Encrypt([]byte("secret"), key)

	// Flip a byte in the ciphertext (after nonce)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	_, err := enc.Decrypt(tampered, key)
	if err == nil {
		t.Error("decrypt of tampered ciphertext should fail")
	}
}

func TestAESEncryptor_TruncatedCiphertext(t *testing.T) {
	enc := crypto.NewAESEncryptor()
	key := validKey(t)

	_, err := enc.Decrypt([]byte("short"), key)
	if err == nil {
		t.Error("decrypt of truncated ciphertext should fail")
	}
}

func TestAESEncryptor_EmptyCiphertext(t *testing.T) {
	enc := crypto.NewAESEncryptor()
	key := validKey(t)

	_, err := enc.Decrypt([]byte{}, key)
	if err == nil {
		t.Error("decrypt of empty ciphertext should fail")
	}
}
