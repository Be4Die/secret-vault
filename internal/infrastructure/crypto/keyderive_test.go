package crypto_test

import (
	"bytes"
	"testing"

	"secret-vault/internal/infrastructure/crypto"
)

func TestKeyDeriver_Deterministic(t *testing.T) {
	d := crypto.NewKeyDeriver()
	salt := []byte("test-salt-value")

	key1 := d.DeriveKey("my passphrase", salt)
	key2 := d.DeriveKey("my passphrase", salt)

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs should produce same key")
	}
}

func TestKeyDeriver_KeyLength(t *testing.T) {
	d := crypto.NewKeyDeriver()
	salt := []byte("salt")

	key := d.DeriveKey("passphrase", salt)
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}
}

func TestKeyDeriver_DifferentPassphrase(t *testing.T) {
	d := crypto.NewKeyDeriver()
	salt := []byte("same-salt")

	key1 := d.DeriveKey("passphrase-one", salt)
	key2 := d.DeriveKey("passphrase-two", salt)

	if bytes.Equal(key1, key2) {
		t.Error("different passphrases should produce different keys")
	}
}

func TestKeyDeriver_DifferentSalt(t *testing.T) {
	d := crypto.NewKeyDeriver()

	key1 := d.DeriveKey("same-passphrase", []byte("salt-one"))
	key2 := d.DeriveKey("same-passphrase", []byte("salt-two"))

	if bytes.Equal(key1, key2) {
		t.Error("different salts should produce different keys")
	}
}

func TestKeyDeriver_UsableWithAES(t *testing.T) {
	d := crypto.NewKeyDeriver()
	enc := crypto.NewAESEncryptor()

	key := d.DeriveKey("user mnemonic phrase", []byte("user-salt"))
	plaintext := []byte("sensitive data")

	ciphertext, err := enc.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt with derived key: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt with derived key: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("roundtrip with derived key failed")
	}
}
