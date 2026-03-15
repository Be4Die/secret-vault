package usecase_test

import (
	"strings"
	"testing"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func TestPasswordUseCase_Generate_Success(t *testing.T) {
	uc := usecase.NewPasswordUseCase()

	tests := []struct {
		name   string
		params entity.PasswordParams
	}{
		{
			name:   "all charsets",
			params: entity.PasswordParams{Length: 16, Uppercase: true, Lowercase: true, Digits: true, Symbols: true},
		},
		{
			name:   "only lowercase",
			params: entity.PasswordParams{Length: 8, Lowercase: true},
		},
		{
			name:   "only uppercase",
			params: entity.PasswordParams{Length: 10, Uppercase: true},
		},
		{
			name:   "only digits",
			params: entity.PasswordParams{Length: 6, Digits: true},
		},
		{
			name:   "only symbols",
			params: entity.PasswordParams{Length: 12, Symbols: true},
		},
		{
			name:   "minimum length",
			params: entity.PasswordParams{Length: 4, Lowercase: true, Uppercase: true, Digits: true, Symbols: true},
		},
		{
			name:   "maximum length",
			params: entity.PasswordParams{Length: 128, Lowercase: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := uc.Generate(tt.params)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(password) != tt.params.Length {
				t.Errorf("expected length %d, got %d", tt.params.Length, len(password))
			}
		})
	}
}

func TestPasswordUseCase_Generate_ContainsRequiredCharsets(t *testing.T) {
	uc := usecase.NewPasswordUseCase()

	params := entity.PasswordParams{
		Length:    32,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
	}

	// Generate many times to increase confidence
	for i := 0; i < 50; i++ {
		password, err := uc.Generate(params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
		hasDigit := strings.ContainsAny(password, "0123456789")
		hasSymbol := strings.ContainsAny(password, "!@#$%^&*()-_=+[]{}|;:,.<>?")

		if !hasUpper {
			t.Error("expected uppercase character")
		}
		if !hasLower {
			t.Error("expected lowercase character")
		}
		if !hasDigit {
			t.Error("expected digit")
		}
		if !hasSymbol {
			t.Error("expected symbol")
		}
	}
}

func TestPasswordUseCase_Generate_OnlyLowercase(t *testing.T) {
	uc := usecase.NewPasswordUseCase()

	params := entity.PasswordParams{Length: 20, Lowercase: true}

	password, err := uc.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range password {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz", c) {
			t.Errorf("unexpected character %q in lowercase-only password", string(c))
		}
	}
}

func TestPasswordUseCase_Generate_OnlyDigits(t *testing.T) {
	uc := usecase.NewPasswordUseCase()

	params := entity.PasswordParams{Length: 20, Digits: true}

	password, err := uc.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range password {
		if !strings.ContainsRune("0123456789", c) {
			t.Errorf("unexpected character %q in digit-only password", string(c))
		}
	}
}

func TestPasswordUseCase_Generate_ValidationError(t *testing.T) {
	uc := usecase.NewPasswordUseCase()

	tests := []struct {
		name   string
		params entity.PasswordParams
	}{
		{
			name:   "too short",
			params: entity.PasswordParams{Length: 3, Lowercase: true},
		},
		{
			name:   "too long",
			params: entity.PasswordParams{Length: 129, Lowercase: true},
		},
		{
			name:   "no charsets",
			params: entity.PasswordParams{Length: 16},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.Generate(tt.params)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestPasswordUseCase_Generate_Uniqueness(t *testing.T) {
	uc := usecase.NewPasswordUseCase()

	params := entity.PasswordParams{
		Length:    32,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
	}

	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		password, err := uc.Generate(params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if passwords[password] {
			t.Errorf("generated duplicate password: %q", password)
		}
		passwords[password] = true
	}
}
