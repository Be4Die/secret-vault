package entity_test

import (
	"testing"
	"time"

	"secret-vault/internal/entity"
)

func TestSession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired — future",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired — past",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "expired — just now",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := entity.Session{ExpiresAt: tt.expiresAt}
			got := s.IsExpired()
			if got != tt.want {
				t.Errorf("IsExpired() = %v, want %v (expiresAt: %v)", got, tt.want, tt.expiresAt)
			}
		})
	}
}
