package crypto_test

import (
	"testing"

	"secret-vault/internal/infrastructure/crypto"
)

func TestMnemonicHasher_Deterministic(t *testing.T) {
	h := crypto.NewMnemonicHasher()

	hash1 := h.HashForAuth("word1 word2 word3")
	hash2 := h.HashForAuth("word1 word2 word3")

	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}
}

func TestMnemonicHasher_DifferentInputs(t *testing.T) {
	h := crypto.NewMnemonicHasher()

	hash1 := h.HashForAuth("word1 word2 word3")
	hash2 := h.HashForAuth("word4 word5 word6")

	if hash1 == hash2 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestMnemonicHasher_Format(t *testing.T) {
	h := crypto.NewMnemonicHasher()

	hash := h.HashForAuth("test mnemonic")

	// SHA-256 produces 64-char hex string
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex string, got %d chars", len(hash))
	}

	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("invalid hex character: %c", c)
		}
	}
}

func TestMnemonicHasher_NotPlaintext(t *testing.T) {
	h := crypto.NewMnemonicHasher()

	input := "hello world"
	hash := h.HashForAuth(input)

	if hash == input {
		t.Error("hash should differ from input")
	}
}
