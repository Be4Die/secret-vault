package crypto

import (
	"fmt"

	"github.com/cosmos/go-bip39"
)

type MnemonicGenerator struct{}

func NewMnemonicGenerator() *MnemonicGenerator {
	return &MnemonicGenerator{}
}

func (g *MnemonicGenerator) Generate() (string, error) {
	entropy, err := bip39.NewEntropy(128) // 128 bits = 12 words
	if err != nil {
		return "", fmt.Errorf("generating entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("generating mnemonic: %w", err)
	}

	return mnemonic, nil
}
