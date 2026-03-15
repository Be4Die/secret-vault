package entity_test

import (
	"testing"

	"secret-vault/internal/entity"
)

func TestUser_Validate(t *testing.T) {
	tests := []struct {
		name    string
		user    entity.User
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid user",
			user:    entity.User{Username: "alice"},
			wantErr: false,
		},
		{
			name:    "valid user max length",
			user:    entity.User{Username: "a_very_long_username_that_is_ok"},
			wantErr: false,
		},
		{
			name:    "empty username",
			user:    entity.User{Username: ""},
			wantErr: true,
			errMsg:  "username is required",
		},
		{
			name:    "whitespace only username",
			user:    entity.User{Username: "   "},
			wantErr: true,
			errMsg:  "username is required",
		},
		{
			name:    "username too short",
			user:    entity.User{Username: "ab"},
			wantErr: true,
			errMsg:  "username must be at least 3 characters",
		},
		{
			name:    "username too long",
			user:    entity.User{Username: "this_username_is_way_too_long_abc"},
			wantErr: true,
			errMsg:  "username must be at most 32 characters",
		},
		{
			name:    "username exactly 3 chars",
			user:    entity.User{Username: "bob"},
			wantErr: false,
		},
		{
			name:    "username exactly 32 chars",
			user:    entity.User{Username: "abcdefghijklmnopqrstuvwxyz123456"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()
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
