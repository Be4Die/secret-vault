package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func newAccountUseCase(
	sessions *mockSessionRepository,
	secrets *mockSecretRepository,
	keyStore *mockKeyStore,
	enc *mockEncryptor,
) *usecase.AccountUseCase {
	if sessions == nil {
		sessions = newMockSessionRepository()
	}
	if secrets == nil {
		secrets = newMockSecretRepository()
	}
	if keyStore == nil {
		keyStore = newMockKeyStore()
	}
	if enc == nil {
		enc = &mockEncryptor{}
	}
	return usecase.NewAccountUseCase(sessions, secrets, keyStore, enc, newMockIDGenerator())
}

func TestAccountUseCase_ListSessions_Success(t *testing.T) {
	sessions := newMockSessionRepository()
	now := time.Now()

	sessions.sessions["s1"] = entity.Session{
		ID: "s1", UserID: "user1", IPAddress: "1.2.3.4",
		UserAgent: "Chrome", LastUsedAt: now, CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	sessions.sessions["s2"] = entity.Session{
		ID: "s2", UserID: "user1", IPAddress: "5.6.7.8",
		UserAgent: "Firefox", LastUsedAt: now, CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	// Expired session — should be filtered out
	sessions.sessions["s3"] = entity.Session{
		ID: "s3", UserID: "user1", IPAddress: "9.0.0.1",
		UserAgent: "Safari", LastUsedAt: now, CreatedAt: now,
		ExpiresAt: now.Add(-1 * time.Hour),
	}

	uc := newAccountUseCase(sessions, nil, nil, nil)

	views, err := uc.ListSessions(context.Background(), "user1", "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(views))
	}

	foundCurrent := false
	for _, v := range views {
		if v.IsCurrent {
			foundCurrent = true
			if v.ID != "s1" {
				t.Errorf("expected current session 's1', got %q", v.ID)
			}
		}
	}
	if !foundCurrent {
		t.Error("expected to find current session")
	}
}

func TestAccountUseCase_ListSessions_RepoError(t *testing.T) {
	sessions := newMockSessionRepository()
	sessions.listByUserIDErr = errors.New("db error")
	uc := newAccountUseCase(sessions, nil, nil, nil)

	_, err := uc.ListSessions(context.Background(), "user1", "s1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountUseCase_TerminateSession_Success(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()
	now := time.Now()

	sessions.sessions["s1"] = entity.Session{
		ID: "s1", UserID: "user1", ExpiresAt: now.Add(24 * time.Hour),
	}
	sessions.sessions["s2"] = entity.Session{
		ID: "s2", UserID: "user1", ExpiresAt: now.Add(24 * time.Hour),
	}
	keyStore.Set("s2", []byte("key"))

	uc := newAccountUseCase(sessions, nil, keyStore, nil)

	err := uc.TerminateSession(context.Background(), "user1", "s2", "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := sessions.sessions["s2"]; ok {
		t.Error("session s2 should be deleted")
	}
	if _, ok := keyStore.Get("s2"); ok {
		t.Error("key for s2 should be deleted")
	}
}

func TestAccountUseCase_TerminateSession_CurrentSession(t *testing.T) {
	uc := newAccountUseCase(nil, nil, nil, nil)

	err := uc.TerminateSession(context.Background(), "user1", "s1", "s1")
	if !errors.Is(err, entity.ErrCurrentSession) {
		t.Errorf("expected ErrCurrentSession, got %v", err)
	}
}

func TestAccountUseCase_TerminateSession_AccessDenied(t *testing.T) {
	sessions := newMockSessionRepository()
	now := time.Now()
	sessions.sessions["s2"] = entity.Session{
		ID: "s2", UserID: "user2", ExpiresAt: now.Add(24 * time.Hour),
	}

	uc := newAccountUseCase(sessions, nil, nil, nil)

	err := uc.TerminateSession(context.Background(), "user1", "s2", "s1")
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestAccountUseCase_TerminateSession_NotFound(t *testing.T) {
	uc := newAccountUseCase(nil, nil, nil, nil)

	err := uc.TerminateSession(context.Background(), "user1", "nonexistent", "s1")
	if !errors.Is(err, entity.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestAccountUseCase_TerminateOtherSessions_Success(t *testing.T) {
	sessions := newMockSessionRepository()
	keyStore := newMockKeyStore()
	now := time.Now()

	sessions.sessions["s1"] = entity.Session{
		ID: "s1", UserID: "user1", ExpiresAt: now.Add(24 * time.Hour),
	}
	sessions.sessions["s2"] = entity.Session{
		ID: "s2", UserID: "user1", ExpiresAt: now.Add(24 * time.Hour),
	}
	sessions.sessions["s3"] = entity.Session{
		ID: "s3", UserID: "user1", ExpiresAt: now.Add(24 * time.Hour),
	}
	keyStore.Set("s1", []byte("key1"))
	keyStore.Set("s2", []byte("key2"))
	keyStore.Set("s3", []byte("key3"))

	uc := newAccountUseCase(sessions, nil, keyStore, nil)

	err := uc.TerminateOtherSessions(context.Background(), "user1", "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := sessions.sessions["s1"]; !ok {
		t.Error("current session s1 should remain")
	}
	if _, ok := keyStore.Get("s1"); !ok {
		t.Error("key for s1 should remain")
	}

	if _, ok := keyStore.Get("s2"); ok {
		t.Error("key for s2 should be deleted")
	}
	if _, ok := keyStore.Get("s3"); ok {
		t.Error("key for s3 should be deleted")
	}
}

func TestAccountUseCase_TerminateOtherSessions_RepoError(t *testing.T) {
	sessions := newMockSessionRepository()
	sessions.listByUserIDErr = errors.New("db error")

	uc := newAccountUseCase(sessions, nil, nil, nil)

	err := uc.TerminateOtherSessions(context.Background(), "user1", "s1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountUseCase_Export_Credentials(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	idGen := newMockIDGenerator()

	credUC := usecase.NewCredentialUseCase(secrets, enc, idGen)
	_, _ = credUC.Create(context.Background(), "user1", testKey, validCredentialPayload())

	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, idGen)

	data, filename, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportCredentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filename != "credentials_export.csv.enc" {
		t.Errorf("expected filename 'credentials_export.csv.enc', got %q", filename)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestAccountUseCase_Export_Tokens(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	idGen := newMockIDGenerator()

	tokenUC := usecase.NewTokenUseCase(secrets, enc, idGen)
	_, _ = tokenUC.Create(context.Background(), "user1", testKey, validTokenPayload())

	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, idGen)

	_, filename, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filename != "tokens_export.csv.enc" {
		t.Errorf("expected filename 'tokens_export.csv.enc', got %q", filename)
	}
}

func TestAccountUseCase_Export_All(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	idGen := newMockIDGenerator()

	credUC := usecase.NewCredentialUseCase(secrets, enc, idGen)
	_, _ = credUC.Create(context.Background(), "user1", testKey, validCredentialPayload())

	tokenUC := usecase.NewTokenUseCase(secrets, enc, idGen)
	_, _ = tokenUC.Create(context.Background(), "user1", testKey, validTokenPayload())

	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, idGen)

	_, filename, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filename != "vault_export.csv.enc" {
		t.Errorf("expected filename 'vault_export.csv.enc', got %q", filename)
	}
}

func TestAccountUseCase_Export_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.listByUserAndTypeErr = errors.New("db error")

	uc := newAccountUseCase(nil, secrets, nil, nil)

	_, _, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportCredentials)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountUseCase_Export_DecryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	idGen := newMockIDGenerator()

	credUC := usecase.NewCredentialUseCase(secrets, enc, idGen)
	_, _ = credUC.Create(context.Background(), "user1", testKey, validCredentialPayload())

	enc.decryptErr = errors.New("decrypt failed")

	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, idGen)

	_, _, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportCredentials)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountUseCase_Export_EncryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}

	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, newMockIDGenerator())

	enc.encryptErr = errors.New("encrypt failed")

	_, _, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportAll)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountUseCase_ImportExport_Roundtrip(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	idGen := newMockIDGenerator()

	credUC := usecase.NewCredentialUseCase(secrets, enc, idGen)
	_, _ = credUC.Create(context.Background(), "user1", testKey, validCredentialPayload())

	tokenUC := usecase.NewTokenUseCase(secrets, enc, idGen)
	_, _ = tokenUC.Create(context.Background(), "user1", testKey, validTokenPayload())

	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, idGen)

	exported, _, err := uc.Export(context.Background(), "user1", testKey, usecase.ExportAll)
	if err != nil {
		t.Fatalf("export error: %v", err)
	}

	// Import into a fresh repository
	importSecrets := newMockSecretRepository()
	importUC := usecase.NewAccountUseCase(nil, importSecrets, nil, enc, idGen)

	count, err := importUC.Import(context.Background(), "user2", testKey, exported)
	if err != nil {
		t.Fatalf("import error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 imported, got %d", count)
	}
	if len(importSecrets.secrets) != 2 {
		t.Errorf("expected 2 secrets in repo, got %d", len(importSecrets.secrets))
	}
}

func TestAccountUseCase_Import_DecryptError(t *testing.T) {
	enc := &mockEncryptor{decryptErr: errors.New("decrypt failed")}
	uc := newAccountUseCase(nil, nil, nil, enc)

	_, err := uc.Import(context.Background(), "user1", testKey, []byte("enc:whatever"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountUseCase_Import_InvalidCSV(t *testing.T) {
	enc := &mockEncryptor{}
	uc := newAccountUseCase(nil, nil, nil, enc)

	encrypted, _ := enc.Encrypt([]byte(""), testKey)

	_, err := uc.Import(context.Background(), "user1", testKey, encrypted)
	if err == nil {
		t.Fatal("expected error for empty CSV")
	}
}

func TestAccountUseCase_Import_InvalidHeader(t *testing.T) {
	enc := &mockEncryptor{}
	uc := newAccountUseCase(nil, nil, nil, enc)

	encrypted, _ := enc.Encrypt([]byte("bad,header\nval1,val2\n"), testKey)

	_, err := uc.Import(context.Background(), "user1", testKey, encrypted)
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
}

func TestAccountUseCase_Import_SkipInvalidRows(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, newMockIDGenerator())

	csv := "type,title,login,password,token,url,note\n" +
		"credential,GitHub,alice,pass,,https://github.com,\n" +
		"unknown_type,Bad,,,,,\n" +
		"credential,,,,,,\n"
	encrypted, _ := enc.Encrypt([]byte(csv), testKey)

	count, err := uc.Import(context.Background(), "user1", testKey, encrypted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 imported (skipping invalid), got %d", count)
	}
}

func TestAccountUseCase_Import_TokenRows(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := usecase.NewAccountUseCase(nil, secrets, nil, enc, newMockIDGenerator())

	csv := "type,title,login,password,token,url,note\n" +
		"token,OpenAI,,,sk-abc123,,my key\n"
	encrypted, _ := enc.Encrypt([]byte(csv), testKey)

	count, err := uc.Import(context.Background(), "user1", testKey, encrypted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 imported, got %d", count)
	}
}

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			name: "Chrome on Windows",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want: "Chrome on Windows",
		},
		{
			name: "Firefox on Linux",
			ua:   "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			want: "Firefox on Linux",
		},
		{
			name: "Safari on macOS",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			want: "Safari on macOS",
		},
		{
			name: "Edge on Windows",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			want: "Edge on Windows",
		},
		{
			name: "Chrome on Android",
			ua:   "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			want: "Chrome on Android",
		},
		{
			name: "Safari on iOS",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			want: "Safari on iOS",
		},
		{
			name: "Opera on Windows",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
			want: "Opera on Windows",
		},
		{
			name: "unknown",
			ua:   "SomeBot/1.0",
			want: "Unknown Browser on Unknown OS",
		},
		{
			name: "empty",
			ua:   "",
			want: "Unknown Browser on Unknown OS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := usecase.ParseUserAgent(tt.ua)
			if got != tt.want {
				t.Errorf("ParseUserAgent(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}
