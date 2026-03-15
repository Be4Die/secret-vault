package crypto_test

import (
	"strings"
	"testing"

	"secret-vault/internal/infrastructure/crypto"
)

func TestMnemonicGenerator_Generate(t *testing.T) {
	g := crypto.NewMnemonicGenerator()

	mnemonic, err := g.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 12 {
		t.Errorf("expected 12 words, got %d: %q", len(words), mnemonic)
	}

	for _, w := range words {
		if len(w) < 3 {
			t.Errorf("word too short: %q", w)
		}
	}
}

func TestMnemonicGenerator_Unique(t *testing.T) {
	g := crypto.NewMnemonicGenerator()

	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		m, err := g.Generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if seen[m] {
			t.Errorf("duplicate mnemonic: %q", m)
		}
		seen[m] = true
	}
}

func TestMnemonicGenerator_AllLowercase(t *testing.T) {
	g := crypto.NewMnemonicGenerator()

	m, _ := g.Generate()
	if m != strings.ToLower(m) {
		t.Errorf("mnemonic should be all lowercase: %q", m)
	}
}
