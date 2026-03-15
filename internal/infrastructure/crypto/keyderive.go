package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

const keySize = 32 // AES-256

type KeyDeriver struct{}

func NewKeyDeriver() *KeyDeriver {
	return &KeyDeriver{}
}

func (d *KeyDeriver) DeriveKey(passphrase string, salt []byte) []byte {
	reader := hkdf.New(sha256.New, []byte(passphrase), salt, []byte("secret-vault-encryption"))
	key := make([]byte, keySize)
	_, _ = reader.Read(key)
	return key
}
