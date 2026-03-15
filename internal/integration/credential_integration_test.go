//go:build integration

package integration_test

import (
	"errors"
	"testing"

	"secret-vault/internal/entity"
)

func TestCredential_CreateAndList(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")

	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	payload := entity.CredentialPayload{
		Title:    "GitHub",
		Login:    "alice@github.com",
		Password: "s3cret!",
		URL:      "https://github.com",
		Note:     "work account",
	}

	id, err := env.credentialUC.Create(ctx, user.ID, key, payload)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty ID")
	}

	// Create another
	_, err = env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "GitLab", Login: "alice", Password: "pass2",
	})
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}

	views, err := env.credentialUC.List(ctx, user.ID, key)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(views) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(views))
	}
}

func TestCredential_GetByID_DecryptsCorrectly(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")

	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	payload := entity.CredentialPayload{
		Title:    "AWS Console",
		Login:    "admin@aws",
		Password: "SuperSecret123!",
		URL:      "https://aws.amazon.com",
		Note:     "root account",
	}

	id, _ := env.credentialUC.Create(ctx, user.ID, key, payload)

	view, err := env.credentialUC.GetByID(ctx, user.ID, id, key)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}

	if view.Payload.Title != "AWS Console" {
		t.Errorf("title: expected 'AWS Console', got %q", view.Payload.Title)
	}
	if view.Payload.Login != "admin@aws" {
		t.Errorf("login: expected 'admin@aws', got %q", view.Payload.Login)
	}
	if view.Payload.Password != "SuperSecret123!" {
		t.Errorf("password: expected 'SuperSecret123!', got %q", view.Payload.Password)
	}
	if view.Payload.URL != "https://aws.amazon.com" {
		t.Errorf("url mismatch")
	}
	if view.Payload.Note != "root account" {
		t.Errorf("note mismatch")
	}
}

func TestCredential_Update(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")

	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	id, _ := env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "Old Title", Login: "old", Password: "oldpass",
	})

	err := env.credentialUC.Update(ctx, user.ID, id, key, entity.CredentialPayload{
		Title: "New Title", Login: "new", Password: "newpass",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	view, _ := env.credentialUC.GetByID(ctx, user.ID, id, key)
	if view.Payload.Title != "New Title" {
		t.Errorf("expected 'New Title', got %q", view.Payload.Title)
	}
	if view.Payload.Password != "newpass" {
		t.Errorf("expected 'newpass', got %q", view.Payload.Password)
	}
}

func TestCredential_Delete(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")

	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	id, _ := env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "ToDelete", Login: "x", Password: "x",
	})

	if err := env.credentialUC.Delete(ctx, user.ID, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := env.credentialUC.GetByID(ctx, user.ID, id, key)
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestCredential_AccessDenied(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, keyAlice, _ := registerTestUser(t, env, "alice")
	_, keyBob, _ := registerTestUser(t, env, "bobuser")

	alice, _ := env.userRepo.GetByUsername(ctx, "alice")
	bob, _ := env.userRepo.GetByUsername(ctx, "bobuser")

	id, _ := env.credentialUC.Create(ctx, alice.ID, keyAlice, entity.CredentialPayload{
		Title: "Alice Secret", Login: "alice", Password: "pass",
	})

	// Bob tries to read Alice's credential
	_, err := env.credentialUC.GetByID(ctx, bob.ID, id, keyBob)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}

	// Bob tries to delete
	err = env.credentialUC.Delete(ctx, bob.ID, id)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied on delete, got %v", err)
	}
}

func TestCredential_WrongKeyCannotDecrypt(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")

	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	id, _ := env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "Secret", Login: "x", Password: "x",
	})

	wrongKey := make([]byte, 32)
	copy(wrongKey, "this-is-a-wrong-key-for-testing!")

	_, err := env.credentialUC.GetByID(ctx, user.ID, id, wrongKey)
	if err == nil {
		t.Error("expected decryption error with wrong key")
	}
}
