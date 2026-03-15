package entity_test

import (
	"strings"
	"testing"

	"secret-vault/internal/entity"
)

func TestCredentialPayload_Validate(t *testing.T) {
	validPayload := entity.CredentialPayload{
		Title:    "GitHub",
		Login:    "alice@example.com",
		Password: "s3cr3t",
	}

	tests := []struct {
		name    string
		payload entity.CredentialPayload
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid full payload",
			payload: entity.CredentialPayload{
				Title:    "GitHub",
				Login:    "alice",
				Password: "pass",
				URL:      "https://github.com",
				Note:     "my work account",
			},
			wantErr: false,
		},
		{
			name:    "valid minimal payload",
			payload: validPayload,
			wantErr: false,
		},
		{
			name:    "empty title",
			payload: entity.CredentialPayload{Login: "alice", Password: "pass"},
			wantErr: true,
			errMsg:  "title is required",
		},
		{
			name:    "whitespace title",
			payload: entity.CredentialPayload{Title: "  ", Login: "alice", Password: "pass"},
			wantErr: true,
			errMsg:  "title is required",
		},
		{
			name: "title too long",
			payload: entity.CredentialPayload{
				Title:    strings.Repeat("a", 129),
				Login:    "alice",
				Password: "pass",
			},
			wantErr: true,
			errMsg:  "title must be at most 128 characters",
		},
		{
			name:    "empty login",
			payload: entity.CredentialPayload{Title: "GitHub", Password: "pass"},
			wantErr: true,
			errMsg:  "login is required",
		},
		{
			name:    "whitespace login",
			payload: entity.CredentialPayload{Title: "GitHub", Login: "  ", Password: "pass"},
			wantErr: true,
			errMsg:  "login is required",
		},
		{
			name: "login too long",
			payload: entity.CredentialPayload{
				Title:    "GitHub",
				Login:    strings.Repeat("a", 257),
				Password: "pass",
			},
			wantErr: true,
			errMsg:  "login must be at most 256 characters",
		},
		{
			name:    "empty password",
			payload: entity.CredentialPayload{Title: "GitHub", Login: "alice"},
			wantErr: true,
			errMsg:  "password is required",
		},
		{
			name:    "whitespace password",
			payload: entity.CredentialPayload{Title: "GitHub", Login: "alice", Password: "  "},
			wantErr: true,
			errMsg:  "password is required",
		},
		{
			name: "password too long",
			payload: entity.CredentialPayload{
				Title:    "GitHub",
				Login:    "alice",
				Password: strings.Repeat("a", 1025),
			},
			wantErr: true,
			errMsg:  "password must be at most 1024 characters",
		},
		{
			name: "url too long",
			payload: entity.CredentialPayload{
				Title:    "GitHub",
				Login:    "alice",
				Password: "pass",
				URL:      strings.Repeat("a", 2049),
			},
			wantErr: true,
			errMsg:  "URL must be at most 2048 characters",
		},
		{
			name: "note too long",
			payload: entity.CredentialPayload{
				Title:    "GitHub",
				Login:    "alice",
				Password: "pass",
				Note:     strings.Repeat("a", 4097),
			},
			wantErr: true,
			errMsg:  "note must be at most 4096 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.payload.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("expected no error, got %q", err.Error())
			}
		})
	}
}

func TestTokenPayload_Validate(t *testing.T) {
	tests := []struct {
		name    string
		payload entity.TokenPayload
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid full payload",
			payload: entity.TokenPayload{
				Title: "OpenAI",
				Token: "sk-abc123",
				URL:   "https://api.openai.com",
				Note:  "personal key",
			},
			wantErr: false,
		},
		{
			name:    "valid minimal payload",
			payload: entity.TokenPayload{Title: "API Key", Token: "abc"},
			wantErr: false,
		},
		{
			name:    "empty title",
			payload: entity.TokenPayload{Token: "abc"},
			wantErr: true,
			errMsg:  "title is required",
		},
		{
			name:    "whitespace title",
			payload: entity.TokenPayload{Title: "  ", Token: "abc"},
			wantErr: true,
			errMsg:  "title is required",
		},
		{
			name: "title too long",
			payload: entity.TokenPayload{
				Title: strings.Repeat("a", 129),
				Token: "abc",
			},
			wantErr: true,
			errMsg:  "title must be at most 128 characters",
		},
		{
			name:    "empty token",
			payload: entity.TokenPayload{Title: "OpenAI"},
			wantErr: true,
			errMsg:  "token is required",
		},
		{
			name:    "whitespace token",
			payload: entity.TokenPayload{Title: "OpenAI", Token: "   "},
			wantErr: true,
			errMsg:  "token is required",
		},
		{
			name: "token too long",
			payload: entity.TokenPayload{
				Title: "OpenAI",
				Token: strings.Repeat("a", 4097),
			},
			wantErr: true,
			errMsg:  "token must be at most 4096 characters",
		},
		{
			name: "url too long",
			payload: entity.TokenPayload{
				Title: "OpenAI",
				Token: "abc",
				URL:   strings.Repeat("a", 2049),
			},
			wantErr: true,
			errMsg:  "URL must be at most 2048 characters",
		},
		{
			name: "note too long",
			payload: entity.TokenPayload{
				Title: "OpenAI",
				Token: "abc",
				Note:  strings.Repeat("a", 4097),
			},
			wantErr: true,
			errMsg:  "note must be at most 4096 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.payload.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("expected no error, got %q", err.Error())
			}
		})
	}
}
