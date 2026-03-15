//go:build integration

package integration_test

import (
	"strings"
	"testing"

	"secret-vault/internal/entity"
)

func TestPassword_Generate(t *testing.T) {
	env := newTestEnv(t)

	password, err := env.passwordUC.Generate(entity.PasswordParams{
		Length:    32,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(password) != 32 {
		t.Errorf("expected length 32, got %d", len(password))
	}
}

func TestPassword_GenerateOnlyDigits(t *testing.T) {
	env := newTestEnv(t)

	password, err := env.passwordUC.Generate(entity.PasswordParams{
		Length: 16,
		Digits: true,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	for _, c := range password {
		if c < '0' || c > '9' {
			t.Errorf("expected only digits, found %q in %q", string(c), password)
			break
		}
	}
}

func TestPassword_GenerateContainsRequiredCharsets(t *testing.T) {
	env := newTestEnv(t)

	// Generate many times to ensure required charsets present
	for i := 0; i < 20; i++ {
		password, err := env.passwordUC.Generate(entity.PasswordParams{
			Length:    20,
			Uppercase: true,
			Lowercase: true,
			Digits:    true,
			Symbols:   true,
		})
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
		hasDigit := strings.ContainsAny(password, "0123456789")
		hasSymbol := strings.ContainsAny(password, "!@#$%^&*()-_=+[]{}|;:,.<>?")

		if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
			t.Errorf("password %q missing required charset (upper=%v lower=%v digit=%v symbol=%v)",
				password, hasUpper, hasLower, hasDigit, hasSymbol)
		}
	}
}

func TestPassword_ValidationErrors(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.passwordUC.Generate(entity.PasswordParams{Length: 2, Lowercase: true})
	if err == nil {
		t.Error("expected error for too short length")
	}

	_, err = env.passwordUC.Generate(entity.PasswordParams{Length: 200, Lowercase: true})
	if err == nil {
		t.Error("expected error for too long length")
	}

	_, err = env.passwordUC.Generate(entity.PasswordParams{Length: 16})
	if err == nil {
		t.Error("expected error for no charsets")
	}
}
