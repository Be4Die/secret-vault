package usecase_test

import (
	"context"
	"errors"
	"testing"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func newAuthUseCase(
	users *mockUserRepository,
	sessions *mockSessionRepository,
	keyStore *mockKeyStore,
	hasher *mockPasswordHasher,
) *usecase.AuthUseCase {
	if users == nil {
		users = newMockUserRepository()
	}
	if sessions == nil {
		sessions = newMockSessionRepository()
	}
	if keyStore == nil {
		keyStore = newMockKeyStore()
	}
	if hasher == nil {
		hasher = &mockPasswordHasher{}
	}
	return usecase.NewAuthUseCase(
		users,
		sessions,
		keyStore,
		hasher,
		&mockKeyDeriver{},
		&mockMnemonicGenerator{},
		newMockIDGenerator(),
		&mockMnemonicHasher{},
	)
}

func TestAuthUseCase_InitiateRegistration_Success(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	pending, err := uc.InitiateRegistration(context.Background(), "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pending.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", pending.Username)
	}
	if pending.Mnemonic == "" {
		t.Error("expected non-empty mnemonic")
	}
	if len(pending.Salt) != 32 {
		t.Errorf("expected salt length 32, got %d", len(pending.Salt))
	}
}

func TestAuthUseCase_InitiateRegistration_UserExists(t *testing.T) {
	users := newMockUserRepository()
	users.byName["alice"] = entity.User{ID: "u1", Username: "alice"}

	uc := newAuthUseCase(users, nil, nil, nil)

	_, err := uc.InitiateRegistration(context.Background(), "Alice")
	if !errors.Is(err, entity.ErrUserExists) {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

func TestAuthUseCase_InitiateRegistration_InvalidUsername(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	_, err := uc.InitiateRegistration(context.Background(), "ab")
	if err == nil {
		t.Fatal("expected error for short username")
	}
}

func TestAuthUseCase_InitiateRegistration_EmptyUsername(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	_, err := uc.InitiateRegistration(context.Background(), "   ")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestAuthUseCase_InitiateRegistration_ExistsCheckError(t *testing.T) {
	users := newMockUserRepository()
	users.existsErr = errors.New("db error")

	uc := newAuthUseCase(users, nil, nil, nil)

	_, err := uc.InitiateRegistration(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthUseCase_CompleteRegistration_Success(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()

	uc := newAuthUseCase(nil, sessions, keyStore, nil)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2 word3",
		Salt:     make([]byte, 32),
	}

	session, err := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.UserID == "" {
		t.Error("expected non-empty user ID")
	}
	if session.IPAddress != "1.2.3.4" {
		t.Errorf("expected IP '1.2.3.4', got %q", session.IPAddress)
	}

	// Verify key was stored
	_, ok := keyStore.Get(session.ID)
	if !ok {
		t.Error("expected encryption key to be stored")
	}
}

func TestAuthUseCase_CompleteRegistration_HashError(t *testing.T) {
	hasher := &mockPasswordHasher{hashErr: errors.New("hash failed")}
	uc := newAuthUseCase(nil, nil, nil, hasher)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2 word3",
		Salt:     make([]byte, 32),
	}

	_, err := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "TestAgent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthUseCase_CompleteRegistration_CreateUserError(t *testing.T) {
	users := newMockUserRepository()
	users.createErr = errors.New("db error")

	uc := newAuthUseCase(users, nil, nil, nil)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2 word3",
		Salt:     make([]byte, 32),
	}

	_, err := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "TestAgent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthUseCase_Login_Success(t *testing.T) {
	users := newMockUserRepository()
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()
	hasher := &mockPasswordHasher{}

	uc := newAuthUseCase(users, sessions, keyStore, hasher)

	// First register
	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2 word3",
		Salt:     make([]byte, 32),
	}
	_, err := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	session, err := uc.Login(context.Background(), "Alice", "word1 word2 word3", "5.6.7.8", "LoginAgent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.IPAddress != "5.6.7.8" {
		t.Errorf("expected IP '5.6.7.8', got %q", session.IPAddress)
	}
}

func TestAuthUseCase_Login_UserNotFound(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	_, err := uc.Login(context.Background(), "nobody", "word1 word2", "1.2.3.4", "Agent")
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthUseCase_Login_WrongMnemonic(t *testing.T) {
	users := newMockUserRepository()
	hasher := &mockPasswordHasher{}

	uc := newAuthUseCase(users, nil, nil, hasher)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "correct words here",
		Salt:     make([]byte, 32),
	}
	_, _ = uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	_, err := uc.Login(context.Background(), "alice", "wrong words", "1.2.3.4", "Agent")
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthUseCase_Logout(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()

	uc := newAuthUseCase(nil, sessions, keyStore, nil)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2",
		Salt:     make([]byte, 32),
	}
	session, _ := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	err := uc.Logout(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, ok := keyStore.Get(session.ID)
	if ok {
		t.Error("key should be deleted after logout")
	}

	if _, ok := sessions.sessions[session.ID]; ok {
		t.Error("session should be deleted after logout")
	}
}

func TestAuthUseCase_GetSession_Success(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()

	uc := newAuthUseCase(nil, sessions, keyStore, nil)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2",
		Salt:     make([]byte, 32),
	}
	session, _ := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	got, key, err := uc.GetSession(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("expected session ID %q, got %q", session.ID, got.ID)
	}
	if len(key) == 0 {
		t.Error("expected non-empty key")
	}
}

func TestAuthUseCase_GetSession_NotFound(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	_, _, err := uc.GetSession(context.Background(), "nonexistent")
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestAuthUseCase_GetSession_Expired(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()

	uc := newAuthUseCase(nil, sessions, keyStore, nil)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2",
		Salt:     make([]byte, 32),
	}
	session, _ := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	// Expire the session
	s := sessions.sessions[session.ID]
	s.ExpiresAt = s.CreatedAt.Add(-1)
	sessions.sessions[session.ID] = s

	_, _, err := uc.GetSession(context.Background(), session.ID)
	if !errors.Is(err, entity.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestAuthUseCase_GetSession_KeyMissing(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()

	uc := newAuthUseCase(nil, sessions, keyStore, nil)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2",
		Salt:     make([]byte, 32),
	}
	session, _ := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	// Delete the key from store
	keyStore.Delete(session.ID)

	_, _, err := uc.GetSession(context.Background(), session.ID)
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestAuthUseCase_GetUserByID(t *testing.T) {
	users := newMockUserRepository()
	users.users["u1"] = entity.User{ID: "u1", Username: "alice"}

	uc := newAuthUseCase(users, nil, nil, nil)

	user, err := uc.GetUserByID(context.Background(), "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", user.Username)
	}
}

func TestAuthUseCase_GetUserByID_NotFound(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	_, err := uc.GetUserByID(context.Background(), "nonexistent")
	if !errors.Is(err, entity.ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestAuthUseCase_VerifyMnemonic_Success(t *testing.T) {
	users := newMockUserRepository()
	hasher := &mockPasswordHasher{}

	uc := newAuthUseCase(users, nil, nil, hasher)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "word1 word2",
		Salt:     make([]byte, 32),
	}
	session, _ := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	err := uc.VerifyMnemonic(context.Background(), session.UserID, "word1 word2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthUseCase_VerifyMnemonic_Wrong(t *testing.T) {
	users := newMockUserRepository()
	hasher := &mockPasswordHasher{}

	uc := newAuthUseCase(users, nil, nil, hasher)

	pending := &usecase.PendingRegistration{
		Username: "alice",
		Mnemonic: "correct words",
		Salt:     make([]byte, 32),
	}
	session, _ := uc.CompleteRegistration(context.Background(), pending, "1.2.3.4", "Agent")

	err := uc.VerifyMnemonic(context.Background(), session.UserID, "wrong words")
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthUseCase_VerifyMnemonic_UserNotFound(t *testing.T) {
	uc := newAuthUseCase(nil, nil, nil, nil)

	err := uc.VerifyMnemonic(context.Background(), "nonexistent", "word1 word2")
	if !errors.Is(err, entity.ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}
