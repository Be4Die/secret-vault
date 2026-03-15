package usecase_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func newSearchUseCase(
	secrets *mockSecretRepository,
	enc *mockEncryptor,
	searcher *mockSearcher,
) *usecase.SearchUseCase {
	if secrets == nil {
		secrets = newMockSecretRepository()
	}
	if enc == nil {
		enc = &mockEncryptor{}
	}
	if searcher == nil {
		searcher = newMockSearcher()
	}
	return usecase.NewSearchUseCase(secrets, enc, searcher)
}

func createTestCredential(t *testing.T, secrets *mockSecretRepository, enc *mockEncryptor, id, userID, title, login, url string) {
	t.Helper()
	payload := entity.CredentialPayload{
		Title: title, Login: login, Password: "pass", URL: url,
	}
	data, _ := json.Marshal(payload)
	encrypted, _ := enc.Encrypt(data, testKey)

	secrets.secrets[id] = entity.Secret{
		ID: id, UserID: userID, SecretType: entity.SecretTypeCredential,
		EncryptedPayload: encrypted,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func createTestToken(t *testing.T, secrets *mockSecretRepository, enc *mockEncryptor, id, userID, title, token, url string) {
	t.Helper()
	payload := entity.TokenPayload{
		Title: title, Token: token, URL: url,
	}
	data, _ := json.Marshal(payload)
	encrypted, _ := enc.Encrypt(data, testKey)

	secrets.secrets[id] = entity.Secret{
		ID: id, UserID: userID, SecretType: entity.SecretTypeToken,
		EncryptedPayload: encrypted,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func TestSearchUseCase_SearchCredentials_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestCredential(t, secrets, enc, "c1", "user1", "GitHub", "alice", "https://github.com")
	createTestCredential(t, secrets, enc, "c2", "user1", "GitLab", "bob", "https://gitlab.com")
	createTestCredential(t, secrets, enc, "c3", "user1", "AWS Console", "admin", "https://aws.amazon.com")

	searcher.scores["git|GitHub"] = 0.9
	searcher.scores["git|alice"] = 0.0
	searcher.scores["git|https://github.com"] = 0.5
	searcher.scores["git|GitLab"] = 0.8
	searcher.scores["git|bob"] = 0.0
	searcher.scores["git|https://gitlab.com"] = 0.5
	searcher.scores["git|AWS Console"] = 0.0
	searcher.scores["git|admin"] = 0.0
	searcher.scores["git|https://aws.amazon.com"] = 0.0

	uc := newSearchUseCase(secrets, enc, searcher)

	results, err := uc.SearchCredentials(context.Background(), "user1", testKey, "git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Results should be sorted by score descending
	if results[0].Payload.Title != "GitHub" {
		t.Errorf("expected first result 'GitHub', got %q", results[0].Payload.Title)
	}
	if results[1].Payload.Title != "GitLab" {
		t.Errorf("expected second result 'GitLab', got %q", results[1].Payload.Title)
	}
}

func TestSearchUseCase_SearchCredentials_NoResults(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestCredential(t, secrets, enc, "c1", "user1", "GitHub", "alice", "")

	// All scores are 0 by default
	uc := newSearchUseCase(secrets, enc, searcher)

	results, err := uc.SearchCredentials(context.Background(), "user1", testKey, "zzz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearchUseCase_SearchCredentials_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.listByUserAndTypeErr = errors.New("db error")

	uc := newSearchUseCase(secrets, nil, nil)

	_, err := uc.SearchCredentials(context.Background(), "user1", testKey, "test")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSearchUseCase_SearchCredentials_DecryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestCredential(t, secrets, enc, "c1", "user1", "GitHub", "alice", "")

	enc.decryptErr = errors.New("decrypt failed")

	uc := newSearchUseCase(secrets, enc, searcher)

	// Should skip entries that fail to decrypt
	results, err := uc.SearchCredentials(context.Background(), "user1", testKey, "git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results (decrypt failed), got %d", len(results))
	}
}

func TestSearchUseCase_SearchTokens_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestToken(t, secrets, enc, "t1", "user1", "OpenAI", "sk-abc", "https://api.openai.com")
	createTestToken(t, secrets, enc, "t2", "user1", "AWS Key", "AKID123", "https://aws.com")

	searcher.scores["openai|OpenAI"] = 0.95
	searcher.scores["openai|https://api.openai.com"] = 0.5

	uc := newSearchUseCase(secrets, enc, searcher)

	results, err := uc.SearchTokens(context.Background(), "user1", testKey, "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Payload.Title != "OpenAI" {
		t.Errorf("expected 'OpenAI', got %q", results[0].Payload.Title)
	}
}

func TestSearchUseCase_SearchTokens_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.listByUserAndTypeErr = errors.New("db error")

	uc := newSearchUseCase(secrets, nil, nil)

	_, err := uc.SearchTokens(context.Background(), "user1", testKey, "test")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSearchUseCase_SearchGlobal_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestCredential(t, secrets, enc, "c1", "user1", "GitHub", "alice", "https://github.com")
	createTestToken(t, secrets, enc, "t1", "user1", "GitHub Token", "ghp_abc123xyz", "https://github.com")

	searcher.scores["github|GitHub"] = 0.9
	searcher.scores["github|alice"] = 0.0
	searcher.scores["github|https://github.com"] = 0.6
	searcher.scores["github|GitHub Token"] = 0.85

	uc := newSearchUseCase(secrets, enc, searcher)

	results, err := uc.SearchGlobal(context.Background(), "user1", testKey, "github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Should be sorted by score
	if results[0].Title != "GitHub" {
		t.Errorf("expected first result 'GitHub' (score 0.9), got %q", results[0].Title)
	}
	if results[0].SecretType != entity.SecretTypeCredential {
		t.Errorf("expected first result to be credential")
	}
	if results[1].SecretType != entity.SecretTypeToken {
		t.Errorf("expected second result to be token")
	}
}

func TestSearchUseCase_SearchGlobal_CredentialError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.listByUserAndTypeErr = errors.New("db error")

	uc := newSearchUseCase(secrets, nil, nil)

	_, err := uc.SearchGlobal(context.Background(), "user1", testKey, "test")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSearchUseCase_SearchGlobal_TokenMasking(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestToken(t, secrets, enc, "t1", "user1", "Long Token", "ghp_abcdef123456", "")

	searcher.scores["token|Long Token"] = 0.9
	searcher.scores["token|"] = 0.0

	uc := newSearchUseCase(secrets, enc, searcher)

	results, err := uc.SearchGlobal(context.Background(), "user1", testKey, "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Token should be masked
	subtitle := results[0].Subtitle
	if subtitle == "ghp_abcdef123456" {
		t.Error("token should be masked in subtitle")
	}
	if subtitle != "ghp_••••3456" {
		t.Errorf("expected masked token 'ghp_••••3456', got %q", subtitle)
	}
}

func TestSearchUseCase_SearchGlobal_ShortTokenMasking(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	searcher := newMockSearcher()

	createTestToken(t, secrets, enc, "t1", "user1", "Short", "abc", "")

	searcher.scores["x|Short"] = 0.9
	searcher.scores["x|"] = 0.0

	uc := newSearchUseCase(secrets, enc, searcher)

	results, err := uc.SearchGlobal(context.Background(), "user1", testKey, "x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Subtitle != "••••••••" {
		t.Errorf("expected fully masked short token, got %q", results[0].Subtitle)
	}
}
