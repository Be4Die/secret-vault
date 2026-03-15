package usecase

import (
	"crypto/rand"
	"math/big"

	"secret-vault/internal/entity"
)

const (
	lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars     = "0123456789"
	symbolChars    = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

type PasswordUseCase struct{}

func NewPasswordUseCase() *PasswordUseCase {
	return &PasswordUseCase{}
}

func (uc *PasswordUseCase) Generate(params entity.PasswordParams) (string, error) {
	if err := params.Validate(); err != nil {
		return "", err
	}

	charset := uc.buildCharset(params)

	result := make([]byte, params.Length)
	for i := 0; i < params.Length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[idx.Int64()]
	}

	pos := 0
	if params.Lowercase && pos < params.Length {
		result[pos] = mustRandChar(lowercaseChars)
		pos++
	}
	if params.Uppercase && pos < params.Length {
		result[pos] = mustRandChar(uppercaseChars)
		pos++
	}
	if params.Digits && pos < params.Length {
		result[pos] = mustRandChar(digitChars)
		pos++
	}
	if params.Symbols && pos < params.Length {
		result[pos] = mustRandChar(symbolChars)
	}

	for i := len(result) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		result[i], result[j.Int64()] = result[j.Int64()], result[i]
	}

	return string(result), nil
}

func (uc *PasswordUseCase) buildCharset(params entity.PasswordParams) string {
	var charset string
	if params.Lowercase {
		charset += lowercaseChars
	}
	if params.Uppercase {
		charset += uppercaseChars
	}
	if params.Digits {
		charset += digitChars
	}
	if params.Symbols {
		charset += symbolChars
	}
	return charset
}

func mustRandChar(chars string) byte {
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	return chars[idx.Int64()]
}
