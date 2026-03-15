package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"secret-vault/internal/entity"
)

type CredentialUseCase struct {
	secrets   SecretRepository
	encryptor Encryptor
	idGen     IDGenerator
}

func NewCredentialUseCase(
	secrets SecretRepository,
	encryptor Encryptor,
	idGen IDGenerator,
) *CredentialUseCase {
	return &CredentialUseCase{
		secrets:   secrets,
		encryptor: encryptor,
		idGen:     idGen,
	}
}

func (uc *CredentialUseCase) Create(ctx context.Context, userID string, key []byte, payload entity.CredentialPayload) (string, error) {
	if err := payload.Validate(); err != nil {
		return "", fmt.Errorf("validation: %w", err)
	}

	encrypted, err := uc.encryptPayload(payload, key)
	if err != nil {
		return "", err
	}

	now := time.Now()
	secret := entity.Secret{
		ID:               uc.idGen.NewID(),
		UserID:           userID,
		SecretType:       entity.SecretTypeCredential,
		EncryptedPayload: encrypted,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := uc.secrets.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("creating secret: %w", err)
	}

	return secret.ID, nil
}

func (uc *CredentialUseCase) List(ctx context.Context, userID string, key []byte) ([]CredentialView, error) {
	secrets, err := uc.secrets.ListByUserAndType(ctx, userID, entity.SecretTypeCredential)
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}

	views := make([]CredentialView, 0, len(secrets))
	for _, s := range secrets {
		payload, err := uc.decryptPayload(s.EncryptedPayload, key)
		if err != nil {
			return nil, fmt.Errorf("decrypting secret %s: %w", s.ID, err)
		}
		views = append(views, CredentialView{
			ID:        s.ID,
			Payload:   payload,
			CreatedAt: s.CreatedAt,
			UpdatedAt: s.UpdatedAt,
		})
	}

	return views, nil
}

func (uc *CredentialUseCase) GetByID(ctx context.Context, userID, secretID string, key []byte) (*CredentialView, error) {
	secret, err := uc.secrets.GetByID(ctx, secretID)
	if err != nil {
		return nil, err
	}

	if secret.UserID != userID {
		return nil, entity.ErrAccessDenied
	}

	payload, err := uc.decryptPayload(secret.EncryptedPayload, key)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}

	return &CredentialView{
		ID:        secret.ID,
		Payload:   payload,
		CreatedAt: secret.CreatedAt,
		UpdatedAt: secret.UpdatedAt,
	}, nil
}

func (uc *CredentialUseCase) Update(ctx context.Context, userID, secretID string, key []byte, payload entity.CredentialPayload) error {
	if err := payload.Validate(); err != nil {
		return fmt.Errorf("validation: %w", err)
	}

	secret, err := uc.secrets.GetByID(ctx, secretID)
	if err != nil {
		return err
	}

	if secret.UserID != userID {
		return entity.ErrAccessDenied
	}

	encrypted, err := uc.encryptPayload(payload, key)
	if err != nil {
		return err
	}

	secret.EncryptedPayload = encrypted
	secret.UpdatedAt = time.Now()

	if err := uc.secrets.Update(ctx, secret); err != nil {
		return fmt.Errorf("updating secret: %w", err)
	}

	return nil
}

func (uc *CredentialUseCase) Delete(ctx context.Context, userID, secretID string) error {
	secret, err := uc.secrets.GetByID(ctx, secretID)
	if err != nil {
		return err
	}

	if secret.UserID != userID {
		return entity.ErrAccessDenied
	}

	if err := uc.secrets.Delete(ctx, secretID); err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}

	return nil
}

func (uc *CredentialUseCase) encryptPayload(payload entity.CredentialPayload, key []byte) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	encrypted, err := uc.encryptor.Encrypt(data, key)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload: %w", err)
	}

	return encrypted, nil
}

func (uc *CredentialUseCase) decryptPayload(ciphertext, key []byte) (entity.CredentialPayload, error) {
	data, err := uc.encryptor.Decrypt(ciphertext, key)
	if err != nil {
		return entity.CredentialPayload{}, fmt.Errorf("decrypting: %w", err)
	}

	var payload entity.CredentialPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return entity.CredentialPayload{}, fmt.Errorf("unmarshaling payload: %w", err)
	}

	return payload, nil
}

type CredentialView struct {
	ID        string
	Payload   entity.CredentialPayload
	CreatedAt time.Time
	UpdatedAt time.Time
}
