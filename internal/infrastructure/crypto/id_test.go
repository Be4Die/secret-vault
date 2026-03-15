package crypto_test

import (
	"testing"

	"secret-vault/internal/infrastructure/crypto"
)

func TestIDGenerator_Format(t *testing.T) {
	g := crypto.NewIDGenerator()

	id := g.NewID()

	// 16 random bytes = 32 hex characters
	if len(id) != 32 {
		t.Errorf("expected 32-char ID, got %d: %q", len(id), id)
	}

	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("invalid hex character: %c", c)
		}
	}
}

func TestIDGenerator_Unique(t *testing.T) {
	g := crypto.NewIDGenerator()

	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := g.NewID()
		if seen[id] {
			t.Errorf("duplicate ID: %q", id)
		}
		seen[id] = true
	}
}
