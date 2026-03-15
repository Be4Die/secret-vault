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

func TestSecretRepository_CreateAndGetByID(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSecretRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now().Truncate(time.Second)
	secret := entity.Secret{
		ID:               "sec-1",
		UserID:           "user-1",
		SecretType:       entity.SecretTypeCredential,
		EncryptedPayload: []byte("encrypted-data-here"),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	got, err := repo.GetByID(ctx, "sec-1")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}

	if got.UserID != "user-1" {
		t.Errorf("expected user_id 'user-1', got %q", got.UserID)
	}
	if got.SecretType != entity.SecretTypeCredential {
		t.Errorf("expected type 'credential', got %q", got.SecretType)
	}
	if string(got.EncryptedPayload) != "encrypted-data-here" {
		t.Errorf("payload mismatch")
	}
}

func TestSecretRepository_GetByID_NotFound(t *testing.T) {
	db := newTestDB(t)
	repo := repository.NewSecretRepository(db)

	_, err := repo.GetByID(context.Background(), "nonexistent")
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestSecretRepository_ListByUserAndType(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSecretRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	secrets := []entity.Secret{
		{ID: "s1", UserID: "user-1", SecretType: entity.SecretTypeCredential, EncryptedPayload: []byte("d1"), CreatedAt: now, UpdatedAt: now},
		{ID: "s2", UserID: "user-1", SecretType: entity.SecretTypeCredential, EncryptedPayload: []byte("d2"), CreatedAt: now.Add(1 * time.Second), UpdatedAt: now},
		{ID: "s3", UserID: "user-1", SecretType: entity.SecretTypeToken, EncryptedPayload: []byte("d3"), CreatedAt: now, UpdatedAt: now},
	}

	for _, s := range secrets {
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("create secret %s: %v", s.ID, err)
		}
	}

	creds, err := repo.ListByUserAndType(ctx, "user-1", entity.SecretTypeCredential)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}

	tokens, err := repo.ListByUserAndType(ctx, "user-1", entity.SecretTypeToken)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("expected 1 token, got %d", len(tokens))
	}
}

func TestSecretRepository_ListByUser(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSecretRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")
	seedUser(t, userRepo, "user-2", "bob")

	now := time.Now()
	_ = repo.Create(ctx, entity.Secret{ID: "s1", UserID: "user-1", SecretType: entity.SecretTypeCredential, EncryptedPayload: []byte("d1"), CreatedAt: now, UpdatedAt: now})
	_ = repo.Create(ctx, entity.Secret{ID: "s2", UserID: "user-1", SecretType: entity.SecretTypeToken, EncryptedPayload: []byte("d2"), CreatedAt: now, UpdatedAt: now})
	_ = repo.Create(ctx, entity.Secret{ID: "s3", UserID: "user-2", SecretType: entity.SecretTypeCredential, EncryptedPayload: []byte("d3"), CreatedAt: now, UpdatedAt: now})

	all, err := repo.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 secrets for user-1, got %d", len(all))
	}
}

func TestSecretRepository_Update(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSecretRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	_ = repo.Create(ctx, entity.Secret{
		ID: "s1", UserID: "user-1", SecretType: entity.SecretTypeCredential,
		EncryptedPayload: []byte("old-data"), CreatedAt: now, UpdatedAt: now,
	})

	updated := entity.Secret{
		ID:               "s1",
		EncryptedPayload: []byte("new-data"),
		UpdatedAt:        now.Add(time.Minute),
	}

	if err := repo.Update(ctx, updated); err != nil {
		t.Fatalf("update secret: %v", err)
	}

	got, _ := repo.GetByID(ctx, "s1")
	if string(got.EncryptedPayload) != "new-data" {
		t.Errorf("expected 'new-data', got %q", got.EncryptedPayload)
	}
}

func TestSecretRepository_Delete(t *testing.T) {
	db := newTestDB(t)
	userRepo := repository.NewUserRepository(db)
	repo := repository.NewSecretRepository(db)
	ctx := context.Background()

	seedUser(t, userRepo, "user-1", "alice")

	now := time.Now()
	_ = repo.Create(ctx, entity.Secret{
		ID: "s1", UserID: "user-1", SecretType: entity.SecretTypeCredential,
		EncryptedPayload: []byte("data"), CreatedAt: now, UpdatedAt: now,
	})

	if err := repo.Delete(ctx, "s1"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}

	_, err := repo.GetByID(ctx, "s1")
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound after delete, got %v", err)
	}
}

func TestSecretRepository_ForeignKeyConstraint(t *testing.T) {
	db := newTestDB(t)
	repo := repository.NewSecretRepository(db)

	now := time.Now()
	err := repo.Create(context.Background(), entity.Secret{
		ID: "s1", UserID: "nonexistent", SecretType: entity.SecretTypeCredential,
		EncryptedPayload: []byte("data"), CreatedAt: now, UpdatedAt: now,
	})

	if err == nil {
		t.Error("expected foreign key error, got nil")
	}
}
