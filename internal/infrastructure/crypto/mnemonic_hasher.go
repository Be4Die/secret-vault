package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

type MnemonicHasher struct{}

func NewMnemonicHasher() *MnemonicHasher {
	return &MnemonicHasher{}
}

func (h *MnemonicHasher) HashForAuth(mnemonic string) string {
	hash := sha256.Sum256([]byte(mnemonic))
	return hex.EncodeToString(hash[:])
}
