//go:build integration

package integration_test

import (
	"errors"
	"testing"

	"secret-vault/internal/entity"
)

func TestAuth_FullRegistrationFlow(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	pending, err := env.authUC.InitiateRegistration(ctx, "alice")
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	if pending.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", pending.Username)
	}
	if pending.Mnemonic == "" {
		t.Error("expected non-empty mnemonic")
	}
	if len(pending.Salt) != 32 {
		t.Errorf("expected 32 byte salt, got %d", len(pending.Salt))
	}

	session, err := env.authUC.CompleteRegistration(ctx, pending, "10.0.0.1", "Chrome/120")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if session.ID == "" {
		t.Error("expected non-empty session ID")
	}

	// Verify key is stored
	key, ok := env.keyStore.Get(session.ID)
	if !ok {
		t.Fatal("key not stored")
	}
	if len(key) != 32 {
		t.Errorf("expected 32 byte key, got %d", len(key))
	}

	// Verify user in DB
	user, err := env.authUC.GetUserByID(ctx, session.UserID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("expected 'alice', got %q", user.Username)
	}
}

func TestAuth_DuplicateRegistration(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	registerTestUser(t, env, "alice")

	_, err := env.authUC.InitiateRegistration(ctx, "alice")
	if !errors.Is(err, entity.ErrUserExists) {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

func TestAuth_LoginWithMnemonic(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, _, mnemonic := registerTestUser(t, env, "alice")

	session, err := env.authUC.Login(ctx, "alice", mnemonic, "10.0.0.2", "Firefox/100")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if session.ID == "" {
		t.Error("expected session")
	}
	if session.IPAddress != "10.0.0.2" {
		t.Errorf("expected IP '10.0.0.2', got %q", session.IPAddress)
	}
}

func TestAuth_LoginWithWrongMnemonic(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	registerTestUser(t, env, "alice")

	_, err := env.authUC.Login(ctx, "alice", "wrong wrong wrong wrong wrong wrong", "1.1.1.1", "test")
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuth_LoginNonexistentUser(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.authUC.Login(t.Context(), "nobody", "word word word word word word", "1.1.1.1", "test")
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuth_GetSession(t *testing.T) {
	env := newTestEnv(t)

	sessionID, expectedKey, _ := registerTestUser(t, env, "alice")

	session, key, err := env.authUC.GetSession(t.Context(), sessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("session ID mismatch")
	}
	if string(key) != string(expectedKey) {
		t.Error("encryption key mismatch")
	}
}

func TestAuth_Logout(t *testing.T) {
	env := newTestEnv(t)

	sessionID, _, _ := registerTestUser(t, env, "alice")

	if err := env.authUC.Logout(t.Context(), sessionID); err != nil {
		t.Fatalf("logout: %v", err)
	}

	_, _, err := env.authUC.GetSession(t.Context(), sessionID)
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound after logout, got %v", err)
	}

	_, ok := env.keyStore.Get(sessionID)
	if ok {
		t.Error("key should be deleted after logout")
	}
}

func TestAuth_VerifyMnemonic(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, _, mnemonic := registerTestUser(t, env, "alice")

	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	if err := env.authUC.VerifyMnemonic(ctx, user.ID, mnemonic); err != nil {
		t.Errorf("verify mnemonic failed: %v", err)
	}

	err := env.authUC.VerifyMnemonic(ctx, user.ID, "wrong wrong wrong wrong wrong wrong")
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for wrong mnemonic, got %v", err)
	}
}
