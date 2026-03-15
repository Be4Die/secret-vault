package entity_test

import (
	"errors"
	"testing"

	"secret-vault/internal/entity"
)

func TestPasswordParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  entity.PasswordParams
		wantErr error
	}{
		{
			name: "valid all charsets",
			params: entity.PasswordParams{
				Length:    16,
				Uppercase: true,
				Lowercase: true,
				Digits:    true,
				Symbols:   true,
			},
			wantErr: nil,
		},
		{
			name: "valid minimal — only lowercase",
			params: entity.PasswordParams{
				Length:    4,
				Lowercase: true,
			},
			wantErr: nil,
		},
		{
			name: "valid max length",
			params: entity.PasswordParams{
				Length: 128,
				Digits: true,
			},
			wantErr: nil,
		},
		{
			name: "length too short",
			params: entity.PasswordParams{
				Length:    3,
				Uppercase: true,
			},
			wantErr: entity.ErrPasswordLengthTooShort,
		},
		{
			name: "length zero",
			params: entity.PasswordParams{
				Length:    0,
				Uppercase: true,
			},
			wantErr: entity.ErrPasswordLengthTooShort,
		},
		{
			name: "length too long",
			params: entity.PasswordParams{
				Length:    129,
				Uppercase: true,
			},
			wantErr: entity.ErrPasswordLengthTooLong,
		},
		{
			name: "no charsets selected",
			params: entity.PasswordParams{
				Length: 16,
			},
			wantErr: entity.ErrPasswordNoCharsets,
		},
		{
			name: "valid — only symbols",
			params: entity.PasswordParams{
				Length:  8,
				Symbols: true,
			},
			wantErr: nil,
		},
		{
			name: "valid — only digits",
			params: entity.PasswordParams{
				Length: 10,
				Digits: true,
			},
			wantErr: nil,
		},
		{
			name: "valid — only uppercase",
			params: entity.PasswordParams{
				Length:    4,
				Uppercase: true,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
