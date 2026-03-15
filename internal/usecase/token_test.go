package usecase_test

import (
	"context"
	"errors"
	"testing"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func newTokenUseCase(secrets *mockSecretRepository, enc *mockEncryptor) *usecase.TokenUseCase {
	if secrets == nil {
		secrets = newMockSecretRepository()
	}
	if enc == nil {
		enc = &mockEncryptor{}
	}
	return usecase.NewTokenUseCase(secrets, enc, newMockIDGenerator())
}

func validTokenPayload() entity.TokenPayload {
	return entity.TokenPayload{
		Title: "OpenAI",
		Token: "sk-abc123xyz",
		URL:   "https://api.openai.com",
		Note:  "personal key",
	}
}

func TestTokenUseCase_Create_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, err := uc.Create(context.Background(), "user1", testKey, validTokenPayload())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty ID")
	}
	if len(secrets.secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(secrets.secrets))
	}
}

func TestTokenUseCase_Create_ValidationError(t *testing.T) {
	uc := newTokenUseCase(nil, nil)

	_, err := uc.Create(context.Background(), "user1", testKey, entity.TokenPayload{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestTokenUseCase_Create_EncryptError(t *testing.T) {
	enc := &mockEncryptor{encryptErr: errors.New("encrypt failed")}
	uc := newTokenUseCase(nil, enc)

	_, err := uc.Create(context.Background(), "user1", testKey, validTokenPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_Create_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.createErr = errors.New("db error")
	uc := newTokenUseCase(secrets, nil)

	_, err := uc.Create(context.Background(), "user1", testKey, validTokenPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_List_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	_, _ = uc.Create(context.Background(), "user1", testKey, validTokenPayload())
	_, _ = uc.Create(context.Background(), "user1", testKey, entity.TokenPayload{
		Title: "AWS", Token: "AKID123",
	})

	views, err := uc.List(context.Background(), "user1", testKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(views) != 2 {
		t.Errorf("expected 2 views, got %d", len(views))
	}
}

func TestTokenUseCase_List_Empty(t *testing.T) {
	uc := newTokenUseCase(nil, nil)

	views, err := uc.List(context.Background(), "user1", testKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(views) != 0 {
		t.Errorf("expected 0 views, got %d", len(views))
	}
}

func TestTokenUseCase_List_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.listByUserAndTypeErr = errors.New("db error")
	uc := newTokenUseCase(secrets, nil)

	_, err := uc.List(context.Background(), "user1", testKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_List_DecryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := newTokenUseCase(secrets, enc)

	_, _ = uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	enc.decryptErr = errors.New("decrypt failed")

	_, err := uc.List(context.Background(), "user1", testKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_GetByID_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	view, err := uc.GetByID(context.Background(), "user1", id, testKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if view.Payload.Title != "OpenAI" {
		t.Errorf("expected title 'OpenAI', got %q", view.Payload.Title)
	}
}

func TestTokenUseCase_GetByID_NotFound(t *testing.T) {
	uc := newTokenUseCase(nil, nil)

	_, err := uc.GetByID(context.Background(), "user1", "nonexistent", testKey)
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestTokenUseCase_GetByID_AccessDenied(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	_, err := uc.GetByID(context.Background(), "user2", id, testKey)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestTokenUseCase_GetByID_DecryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := newTokenUseCase(secrets, enc)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	enc.decryptErr = errors.New("decrypt failed")

	_, err := uc.GetByID(context.Background(), "user1", id, testKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_Update_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	updated := entity.TokenPayload{
		Title: "Updated", Token: "new-token-value",
	}
	err := uc.Update(context.Background(), "user1", id, testKey, updated)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	view, _ := uc.GetByID(context.Background(), "user1", id, testKey)
	if view.Payload.Title != "Updated" {
		t.Errorf("expected title 'Updated', got %q", view.Payload.Title)
	}
}

func TestTokenUseCase_Update_ValidationError(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	err := uc.Update(context.Background(), "user1", id, testKey, entity.TokenPayload{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestTokenUseCase_Update_NotFound(t *testing.T) {
	uc := newTokenUseCase(nil, nil)

	err := uc.Update(context.Background(), "user1", "nonexistent", testKey, validTokenPayload())
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestTokenUseCase_Update_AccessDenied(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	err := uc.Update(context.Background(), "user2", id, testKey, validTokenPayload())
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestTokenUseCase_Update_EncryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := newTokenUseCase(secrets, enc)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	enc.encryptErr = errors.New("encrypt failed")

	err := uc.Update(context.Background(), "user1", id, testKey, validTokenPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_Update_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	secrets.updateErr = errors.New("db error")

	err := uc.Update(context.Background(), "user1", id, testKey, validTokenPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenUseCase_Delete_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	err := uc.Delete(context.Background(), "user1", id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets.secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets.secrets))
	}
}

func TestTokenUseCase_Delete_NotFound(t *testing.T) {
	uc := newTokenUseCase(nil, nil)

	err := uc.Delete(context.Background(), "user1", "nonexistent")
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestTokenUseCase_Delete_AccessDenied(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	err := uc.Delete(context.Background(), "user2", id)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestTokenUseCase_Delete_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newTokenUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validTokenPayload())

	secrets.deleteErr = errors.New("db error")

	err := uc.Delete(context.Background(), "user1", id)
	if err == nil {
		t.Fatal("expected error")
	}
}
