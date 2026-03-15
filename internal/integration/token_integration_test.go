//go:build integration

package integration_test

import (
	"errors"
	"testing"

	"secret-vault/internal/entity"
)

func TestToken_CreateAndList(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	_, err := env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "API Key", Token: "sk-abc123def456", URL: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "SSH Key", Token: "ssh-rsa AAAA...", Note: "server access",
	})
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}

	views, err := env.tokenUC.List(ctx, user.ID, key)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(views) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(views))
	}
}

func TestToken_GetByID_DecryptsCorrectly(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	id, _ := env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "Stripe", Token: "sk_live_abc123", URL: "https://stripe.com", Note: "production",
	})

	view, err := env.tokenUC.GetByID(ctx, user.ID, id, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if view.Payload.Token != "sk_live_abc123" {
		t.Errorf("token mismatch: %q", view.Payload.Token)
	}
	if view.Payload.Title != "Stripe" {
		t.Errorf("title mismatch: %q", view.Payload.Title)
	}
}

func TestToken_Update(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	id, _ := env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "Old", Token: "old-token",
	})

	err := env.tokenUC.Update(ctx, user.ID, id, key, entity.TokenPayload{
		Title: "New", Token: "new-token",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	view, _ := env.tokenUC.GetByID(ctx, user.ID, id, key)
	if view.Payload.Token != "new-token" {
		t.Errorf("expected 'new-token', got %q", view.Payload.Token)
	}
}

func TestToken_Delete(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	id, _ := env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "ToDelete", Token: "xxx",
	})

	if err := env.tokenUC.Delete(ctx, user.ID, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := env.tokenUC.GetByID(ctx, user.ID, id, key)
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestToken_AccessDenied(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, keyAlice, _ := registerTestUser(t, env, "alice")
	_, keyBob, _ := registerTestUser(t, env, "bobuser")
	alice, _ := env.userRepo.GetByUsername(ctx, "alice")
	bob, _ := env.userRepo.GetByUsername(ctx, "bobuser")

	id, _ := env.tokenUC.Create(ctx, alice.ID, keyAlice, entity.TokenPayload{
		Title: "Alice Token", Token: "secret",
	})

	_, err := env.tokenUC.GetByID(ctx, bob.ID, id, keyBob)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}
