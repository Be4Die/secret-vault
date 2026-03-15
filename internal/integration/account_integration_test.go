//go:build integration

package integration_test

import (
	"errors"
	"testing"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func TestAccount_ListSessions(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	sessionID, _, mnemonic := registerTestUser(t, env, "alice")

	// Login again from different "device"
	session2, err := env.authUC.Login(ctx, "alice", mnemonic, "10.0.0.2", "Firefox/120")
	if err != nil {
		t.Fatalf("login 2: %v", err)
	}

	user, _ := env.userRepo.GetByUsername(ctx, "alice")
	views, err := env.accountUC.ListSessions(ctx, user.ID, sessionID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}

	if len(views) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(views))
	}

	// Check current session flag
	currentCount := 0
	for _, v := range views {
		if v.IsCurrent {
			currentCount++
			if v.ID != sessionID {
				t.Errorf("wrong session marked as current")
			}
		}
	}
	if currentCount != 1 {
		t.Errorf("expected exactly 1 current session, got %d", currentCount)
	}

	_ = session2 // used above
}

func TestAccount_TerminateSession(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	sessionID, _, mnemonic := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	session2, _ := env.authUC.Login(ctx, "alice", mnemonic, "10.0.0.2", "Firefox")

	// Terminate second session
	err := env.accountUC.TerminateSession(ctx, user.ID, session2.ID, sessionID)
	if err != nil {
		t.Fatalf("terminate: %v", err)
	}

	views, _ := env.accountUC.ListSessions(ctx, user.ID, sessionID)
	if len(views) != 1 {
		t.Errorf("expected 1 session, got %d", len(views))
	}
}

func TestAccount_TerminateCurrentSessionFails(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	sessionID, _, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	err := env.accountUC.TerminateSession(ctx, user.ID, sessionID, sessionID)
	if !errors.Is(err, entity.ErrCurrentSession) {
		t.Errorf("expected ErrCurrentSession, got %v", err)
	}
}

func TestAccount_TerminateOtherSessions(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	sessionID, _, mnemonic := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	// Create 3 more sessions
	for i := 0; i < 3; i++ {
		_, _ = env.authUC.Login(ctx, "alice", mnemonic, "10.0.0.2", "test")
	}

	err := env.accountUC.TerminateOtherSessions(ctx, user.ID, sessionID)
	if err != nil {
		t.Fatalf("terminate others: %v", err)
	}

	views, _ := env.accountUC.ListSessions(ctx, user.ID, sessionID)
	if len(views) != 1 {
		t.Errorf("expected 1 session, got %d", len(views))
	}
	if views[0].ID != sessionID {
		t.Error("wrong session remained")
	}
}

func TestAccount_ExportImportRoundtrip(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	// Create test data
	_, _ = env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "GitHub", Login: "alice", Password: "pass1", URL: "https://github.com", Note: "work",
	})
	_, _ = env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "AWS", Login: "admin", Password: "pass2",
	})
	_, _ = env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "API Key", Token: "sk-abc123",
	})

	// Export all
	data, filename, err := env.accountUC.Export(ctx, user.ID, key, usecase.ExportAll)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if filename != "vault_export.csv.enc" {
		t.Errorf("expected 'vault_export.csv.enc', got %q", filename)
	}
	if len(data) == 0 {
		t.Error("export data is empty")
	}

	// Register new user, import data
	_, key2, _ := registerTestUser(t, env, "bobuser")
	bob, _ := env.userRepo.GetByUsername(ctx, "bobuser")

	// Import with same key (simulating shared export)
	count, err := env.accountUC.Import(ctx, bob.ID, key, data)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 imported, got %d", count)
	}

	// Verify imported credentials can be read with original key
	creds, err := env.credentialUC.List(ctx, bob.ID, key)
	if err != nil {
		t.Fatalf("list imported creds: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}

	tokens, err := env.tokenUC.List(ctx, bob.ID, key)
	if err != nil {
		t.Fatalf("list imported tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("expected 1 token, got %d", len(tokens))
	}

	_ = key2 // bob's own key (different from export key)
}

func TestAccount_ExportByType(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	_, _ = env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "Cred", Login: "x", Password: "x",
	})
	_, _ = env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "Tok", Token: "xxx",
	})

	// Export only credentials
	_, filename, err := env.accountUC.Export(ctx, user.ID, key, usecase.ExportCredentials)
	if err != nil {
		t.Fatalf("export creds: %v", err)
	}
	if filename != "credentials_export.csv.enc" {
		t.Errorf("expected credentials filename, got %q", filename)
	}

	// Export only tokens
	_, filename, err = env.accountUC.Export(ctx, user.ID, key, usecase.ExportTokens)
	if err != nil {
		t.Fatalf("export tokens: %v", err)
	}
	if filename != "tokens_export.csv.enc" {
		t.Errorf("expected tokens filename, got %q", filename)
	}
}
