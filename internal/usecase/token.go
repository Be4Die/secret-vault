package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"secret-vault/internal/entity"
)

type TokenUseCase struct {
	secrets   SecretRepository
	encryptor Encryptor
	idGen     IDGenerator
}

func NewTokenUseCase(
	secrets SecretRepository,
	encryptor Encryptor,
	idGen IDGenerator,
) *TokenUseCase {
	return &TokenUseCase{
		secrets:   secrets,
		encryptor: encryptor,
		idGen:     idGen,
	}
}

type TokenView struct {
	ID        string
	Payload   entity.TokenPayload
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (uc *TokenUseCase) Create(ctx context.Context, userID string, key []byte, payload entity.TokenPayload) (string, error) {
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
		SecretType:       entity.SecretTypeToken,
		EncryptedPayload: encrypted,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := uc.secrets.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("creating secret: %w", err)
	}

	return secret.ID, nil
}

func (uc *TokenUseCase) List(ctx context.Context, userID string, key []byte) ([]TokenView, error) {
	secrets, err := uc.secrets.ListByUserAndType(ctx, userID, entity.SecretTypeToken)
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}

	views := make([]TokenView, 0, len(secrets))
	for _, s := range secrets {
		payload, err := uc.decryptPayload(s.EncryptedPayload, key)
		if err != nil {
			return nil, fmt.Errorf("decrypting secret %s: %w", s.ID, err)
		}
		views = append(views, TokenView{
			ID:        s.ID,
			Payload:   payload,
			CreatedAt: s.CreatedAt,
			UpdatedAt: s.UpdatedAt,
		})
	}

	return views, nil
}

func (uc *TokenUseCase) GetByID(ctx context.Context, userID, secretID string, key []byte) (*TokenView, error) {
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

	return &TokenView{
		ID:        secret.ID,
		Payload:   payload,
		CreatedAt: secret.CreatedAt,
		UpdatedAt: secret.UpdatedAt,
	}, nil
}

func (uc *TokenUseCase) Update(ctx context.Context, userID, secretID string, key []byte, payload entity.TokenPayload) error {
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

func (uc *TokenUseCase) Delete(ctx context.Context, userID, secretID string) error {
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

func (uc *TokenUseCase) encryptPayload(payload entity.TokenPayload, key []byte) ([]byte, error) {
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

func (uc *TokenUseCase) decryptPayload(ciphertext, key []byte) (entity.TokenPayload, error) {
	data, err := uc.encryptor.Decrypt(ciphertext, key)
	if err != nil {
		return entity.TokenPayload{}, fmt.Errorf("decrypting: %w", err)
	}

	var payload entity.TokenPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return entity.TokenPayload{}, fmt.Errorf("unmarshaling payload: %w", err)
	}

	return payload, nil
}
