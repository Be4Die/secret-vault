package usecase_test

import (
	"context"
	"errors"
	"testing"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func newCredentialUseCase(secrets *mockSecretRepository, enc *mockEncryptor) *usecase.CredentialUseCase {
	if secrets == nil {
		secrets = newMockSecretRepository()
	}
	if enc == nil {
		enc = &mockEncryptor{}
	}
	return usecase.NewCredentialUseCase(secrets, enc, newMockIDGenerator())
}

var testKey = []byte("test-key-32-bytes-for-testing!!!")

func validCredentialPayload() entity.CredentialPayload {
	return entity.CredentialPayload{
		Title:    "GitHub",
		Login:    "alice",
		Password: "secret123",
		URL:      "https://github.com",
		Note:     "work account",
	}
}

func TestCredentialUseCase_Create_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, err := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())
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

func TestCredentialUseCase_Create_ValidationError(t *testing.T) {
	uc := newCredentialUseCase(nil, nil)

	_, err := uc.Create(context.Background(), "user1", testKey, entity.CredentialPayload{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestCredentialUseCase_Create_EncryptError(t *testing.T) {
	enc := &mockEncryptor{encryptErr: errors.New("encrypt failed")}
	uc := newCredentialUseCase(nil, enc)

	_, err := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_Create_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.createErr = errors.New("db error")
	uc := newCredentialUseCase(secrets, nil)

	_, err := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_List_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	_, _ = uc.Create(context.Background(), "user1", testKey, validCredentialPayload())
	_, _ = uc.Create(context.Background(), "user1", testKey, entity.CredentialPayload{
		Title: "GitLab", Login: "bob", Password: "pass",
	})

	views, err := uc.List(context.Background(), "user1", testKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(views) != 2 {
		t.Errorf("expected 2 views, got %d", len(views))
	}
}

func TestCredentialUseCase_List_Empty(t *testing.T) {
	uc := newCredentialUseCase(nil, nil)

	views, err := uc.List(context.Background(), "user1", testKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(views) != 0 {
		t.Errorf("expected 0 views, got %d", len(views))
	}
}

func TestCredentialUseCase_List_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	secrets.listByUserAndTypeErr = errors.New("db error")
	uc := newCredentialUseCase(secrets, nil)

	_, err := uc.List(context.Background(), "user1", testKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_List_DecryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := newCredentialUseCase(secrets, enc)

	_, _ = uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	// Now make decryption fail
	enc.decryptErr = errors.New("decrypt failed")

	_, err := uc.List(context.Background(), "user1", testKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_GetByID_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	view, err := uc.GetByID(context.Background(), "user1", id, testKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if view.Payload.Title != "GitHub" {
		t.Errorf("expected title 'GitHub', got %q", view.Payload.Title)
	}
}

func TestCredentialUseCase_GetByID_NotFound(t *testing.T) {
	uc := newCredentialUseCase(nil, nil)

	_, err := uc.GetByID(context.Background(), "user1", "nonexistent", testKey)
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestCredentialUseCase_GetByID_AccessDenied(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	_, err := uc.GetByID(context.Background(), "user2", id, testKey)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestCredentialUseCase_GetByID_DecryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := newCredentialUseCase(secrets, enc)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	enc.decryptErr = errors.New("decrypt failed")

	_, err := uc.GetByID(context.Background(), "user1", id, testKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_Update_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	updated := entity.CredentialPayload{
		Title: "Updated", Login: "newlogin", Password: "newpass",
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

func TestCredentialUseCase_Update_ValidationError(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	err := uc.Update(context.Background(), "user1", id, testKey, entity.CredentialPayload{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestCredentialUseCase_Update_NotFound(t *testing.T) {
	uc := newCredentialUseCase(nil, nil)

	err := uc.Update(context.Background(), "user1", "nonexistent", testKey, validCredentialPayload())
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestCredentialUseCase_Update_AccessDenied(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	err := uc.Update(context.Background(), "user2", id, testKey, validCredentialPayload())
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestCredentialUseCase_Update_EncryptError(t *testing.T) {
	secrets := newMockSecretRepository()
	enc := &mockEncryptor{}
	uc := newCredentialUseCase(secrets, enc)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	enc.encryptErr = errors.New("encrypt failed")

	err := uc.Update(context.Background(), "user1", id, testKey, validCredentialPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_Update_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	secrets.updateErr = errors.New("db error")

	err := uc.Update(context.Background(), "user1", id, testKey, validCredentialPayload())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialUseCase_Delete_Success(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	err := uc.Delete(context.Background(), "user1", id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(secrets.secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets.secrets))
	}
}

func TestCredentialUseCase_Delete_NotFound(t *testing.T) {
	uc := newCredentialUseCase(nil, nil)

	err := uc.Delete(context.Background(), "user1", "nonexistent")
	if !errors.Is(err, entity.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestCredentialUseCase_Delete_AccessDenied(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	err := uc.Delete(context.Background(), "user2", id)
	if !errors.Is(err, entity.ErrAccessDenied) {
		t.Errorf("expected ErrAccessDenied, got %v", err)
	}
}

func TestCredentialUseCase_Delete_RepoError(t *testing.T) {
	secrets := newMockSecretRepository()
	uc := newCredentialUseCase(secrets, nil)

	id, _ := uc.Create(context.Background(), "user1", testKey, validCredentialPayload())

	secrets.deleteErr = errors.New("db error")

	err := uc.Delete(context.Background(), "user1", id)
	if err == nil {
		t.Fatal("expected error")
	}
}
