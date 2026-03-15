//go:build integration

package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"secret-vault/internal/adapter/repository"
	"secret-vault/internal/entity"
)

func createTestUser(t *testing.T, db interface {
	ExecContext(ctx context.Context, query string, args ...any) (interface{ RowsAffected() (int64, error) }, error)
}) {
	t.Helper()
}

func seedUser(t *testing.T, repo *repository.UserRepository, id, username string) {
	t.Helper()
	err := repo.Create(context.Background(), entity.User{
		ID:           id,
		Username:     username,
		PasswordHash: "hash",
		KeySalt:      []byte("salt"),
		CreatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func TestSessionRepository_CreateAndGetByID(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSessionRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now().Truncate(time.Second)
	session := entity.Session{
		ID:         "sess-1",
		UserID:     "user-1",
		IPAddress:  "127.0.0.1",
		UserAgent:  "TestBrowser/1.0",
		LastUsedAt: now,
		CreatedAt:  now,
		ExpiresAt:  now.Add(7 * 24 * time.Hour),
	}

	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	got, err := repo.GetByID(ctx, "sess-1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	if got.UserID != "user-1" {
		t.Errorf("expected user_id 'user-1', got %q", got.UserID)
	}
	if got.IPAddress != "127.0.0.1" {
		t.Errorf("expected IP '127.0.0.1', got %q", got.IPAddress)
	}
}

func TestSessionRepository_GetByID_NotFound(t *testing.T) {
	db := newTestDB(t)
	repo := repository.NewSessionRepository(db)

	_, err := repo.GetByID(context.Background(), "nonexistent")
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionRepository_ListByUserID(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSessionRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")
	seedUser(t, userRepo, "user-2", "bob")

	now := time.Now()
	for i, sid := range []string{"s1", "s2", "s3"} {
		_ = repo.Create(ctx, entity.Session{
			ID:         sid,
			UserID:     "user-1",
			IPAddress:  "1.2.3.4",
			UserAgent:  "test",
			LastUsedAt: now.Add(time.Duration(i) * time.Minute),
			CreatedAt:  now,
			ExpiresAt:  now.Add(time.Hour),
		})
	}

	_ = repo.Create(ctx, entity.Session{
		ID:         "s4",
		UserID:     "user-2",
		IPAddress:  "5.6.7.8",
		UserAgent:  "test",
		LastUsedAt: now,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	})

	sessions, err := repo.ListByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("expected 3 sessions, got %d", len(sessions))
	}

	// Verify order (most recent last_used first)
	if len(sessions) >= 2 && sessions[0].LastUsedAt.Before(sessions[1].LastUsedAt) {
		t.Error("sessions not ordered by last_used_at DESC")
	}
}

func TestSessionRepository_DeleteByID(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSessionRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	_ = repo.Create(ctx, entity.Session{
		ID: "s1", UserID: "user-1", IPAddress: "1.1.1.1", UserAgent: "t",
		LastUsedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	if err := repo.DeleteByID(ctx, "s1"); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	_, err := repo.GetByID(ctx, "s1")
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound after delete, got %v", err)
	}
}

func TestSessionRepository_DeleteByUserIDExcept(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSessionRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	for _, sid := range []string{"s1", "s2", "s3"} {
		_ = repo.Create(ctx, entity.Session{
			ID: sid, UserID: "user-1", IPAddress: "1.1.1.1", UserAgent: "t",
			LastUsedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}

	if err := repo.DeleteByUserIDExcept(ctx, "user-1", "s2"); err != nil {
		t.Fatalf("delete except: %v", err)
	}

	sessions, _ := repo.ListByUserID(ctx, "user-1")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session remaining, got %d", len(sessions))
	}
	if sessions[0].ID != "s2" {
		t.Errorf("expected session 's2' to remain, got %q", sessions[0].ID)
	}
}

func TestSessionRepository_ForeignKeyConstraint(t *testing.T) {
	db := newTestDB(t)
	repo := repository.NewSessionRepository(db)
	ctx := context.Background()

	now := time.Now()
	err := repo.Create(ctx, entity.Session{
		ID: "s1", UserID: "nonexistent-user", IPAddress: "1.1.1.1", UserAgent: "t",
		LastUsedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	if err == nil {
		t.Error("expected foreign key error, got nil")
	}
}

func TestSessionRepository_CascadeDeleteOnUserRemoval(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	_ = sessionRepo.Create(ctx, entity.Session{
		ID: "s1", UserID: "user-1", IPAddress: "1.1.1.1", UserAgent: "t",
		LastUsedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	// Delete user directly via SQL to trigger cascade
	_, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", "user-1")
	if err != nil {
		t.Fatalf("delete user: %v", err)
	}

	_, err = sessionRepo.GetByID(ctx, "s1")
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected session to be cascade-deleted, got %v", err)
	}
}
