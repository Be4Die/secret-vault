package crypto_test

import (
	"testing"

	"secret-vault/internal/infrastructure/crypto"
)

func TestPasswordHasher_HashAndCompare(t *testing.T) {
	h := crypto.NewPasswordHasher()

	password := "my-secure-password"

	hash, err := h.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}
	if hash == password {
		t.Error("hash should differ from password")
	}

	err = h.Compare(password, hash)
	if err != nil {
		t.Errorf("compare should succeed for correct password: %v", err)
	}
}

func TestPasswordHasher_WrongPassword(t *testing.T) {
	h := crypto.NewPasswordHasher()

	hash, _ := h.Hash("correct")

	err := h.Compare("wrong", hash)
	if err == nil {
		t.Error("compare should fail for wrong password")
	}
}

func TestPasswordHasher_DifferentHashes(t *testing.T) {
	h := crypto.NewPasswordHasher()

	hash1, _ := h.Hash("password")
	hash2, _ := h.Hash("password")

	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (bcrypt uses random salt)")
	}
}

func TestPasswordHasher_EmptyPassword(t *testing.T) {
	h := crypto.NewPasswordHasher()

	hash, err := h.Hash("")
	if err != nil {
		t.Fatalf("hash of empty password: %v", err)
	}

	err = h.Compare("", hash)
	if err != nil {
		t.Errorf("compare should succeed for empty password: %v", err)
	}

	err = h.Compare("notempty", hash)
	if err == nil {
		t.Error("compare should fail for non-empty password against empty hash")
	}
}
