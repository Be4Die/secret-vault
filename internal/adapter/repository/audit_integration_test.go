//go:build integration

package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"secret-vault/internal/adapter/repository"
	"secret-vault/internal/entity"
)

func TestAuditRepository_CreateAndList(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewAuditRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	logs := []entity.AuditLog{
		{ID: "a1", UserID: "user-1", Action: entity.AuditActionLogin, Category: entity.AuditCategoryAuth, Detail: "Logged in", IPAddress: "1.1.1.1", UserAgent: "test", CreatedAt: now},
		{ID: "a2", UserID: "user-1", Action: entity.AuditActionCredentialCreated, Category: entity.AuditCategoryCredential, Detail: "GitHub", IPAddress: "1.1.1.1", UserAgent: "test", CreatedAt: now.Add(1 * time.Second)},
		{ID: "a3", UserID: "user-1", Action: entity.AuditActionLogin, Category: entity.AuditCategoryAuth, Detail: "Again", IPAddress: "2.2.2.2", UserAgent: "test2", CreatedAt: now.Add(2 * time.Second)},
	}

	for _, log := range logs {
		if err := repo.Create(ctx, log); err != nil {
			t.Fatalf("create audit log %s: %v", log.ID, err)
		}
	}

	allLogs, err := repo.ListByUser(ctx, "user-1", "", 10, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(allLogs) != 3 {
		t.Errorf("expected 3 logs, got %d", len(allLogs))
	}

	authLogs, err := repo.ListByUser(ctx, "user-1", "auth", 10, 0)
	if err != nil {
		t.Fatalf("list auth: %v", err)
	}
	if len(authLogs) != 2 {
		t.Errorf("expected 2 auth logs, got %d", len(authLogs))
	}
}

func TestAuditRepository_CountByUser(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewAuditRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	for i := 0; i < 5; i++ {
		_ = repo.Create(ctx, entity.AuditLog{
			ID:        fmt.Sprintf("a%d", i),
			UserID:    "user-1",
			Action:    entity.AuditActionLogin,
			Category:  entity.AuditCategoryAuth,
			Detail:    "test",
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}

	count, err := repo.CountByUser(ctx, "user-1", "")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}

	countAuth, err := repo.CountByUser(ctx, "user-1", "auth")
	if err != nil {
		t.Fatalf("count auth: %v", err)
	}
	if countAuth != 5 {
		t.Errorf("expected 5 auth, got %d", countAuth)
	}
}

func TestAuditRepository_Pagination(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewAuditRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	for i := 0; i < 25; i++ {
		_ = repo.Create(ctx, entity.AuditLog{
			ID:        fmt.Sprintf("audit-%d", i),
			UserID:    "user-1",
			Action:    entity.AuditActionLogin,
			Category:  entity.AuditCategoryAuth,
			Detail:    "test",
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}

	page1, err := repo.ListByUser(ctx, "user-1", "", 10, 0)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1) != 10 {
		t.Errorf("page 1: expected 10, got %d", len(page1))
	}

	page3, err := repo.ListByUser(ctx, "user-1", "", 10, 20)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if len(page3) != 5 {
		t.Errorf("page 3: expected 5, got %d", len(page3))
	}
}

func TestAuditRepository_DeleteOlderThan(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewAuditRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now()

	_ = repo.Create(ctx, entity.AuditLog{
		ID: "old-1", UserID: "user-1", Action: entity.AuditActionLogin,
		Category: entity.AuditCategoryAuth, CreatedAt: old,
	})
	_ = repo.Create(ctx, entity.AuditLog{
		ID: "new-1", UserID: "user-1", Action: entity.AuditActionLogin,
		Category: entity.AuditCategoryAuth, CreatedAt: recent,
	})

	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	if err := repo.DeleteOlderThan(ctx, cutoff); err != nil {
		t.Fatalf("delete older: %v", err)
	}

	count, _ := repo.CountByUser(ctx, "user-1", "")
	if count != 1 {
		t.Errorf("expected 1 remaining, got %d", count)
	}
}
