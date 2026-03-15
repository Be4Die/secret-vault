package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"secret-vault/internal/entity"
)

type SecretRepository struct {
	db *sql.DB
}

func NewSecretRepository(db *sql.DB) *SecretRepository {
	return &SecretRepository{db: db}
}

func (r *SecretRepository) Create(ctx context.Context, secret entity.Secret) error {
	query := `INSERT INTO secrets (id, user_id, secret_type, encrypted_payload, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, query,
		secret.ID, secret.UserID, secret.SecretType,
		secret.EncryptedPayload, secret.CreatedAt, secret.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert secret: %w", err)
	}
	return nil
}

func (r *SecretRepository) GetByID(ctx context.Context, id string) (entity.Secret, error) {
	query := `SELECT id, user_id, secret_type, encrypted_payload, created_at, updated_at
		FROM secrets WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)

	var s entity.Secret
	err := row.Scan(&s.ID, &s.UserID, &s.SecretType, &s.EncryptedPayload, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.Secret{}, entity.ErrSecretNotFound
	}
	if err != nil {
		return entity.Secret{}, fmt.Errorf("scan secret: %w", err)
	}
	return s, nil
}

func (r *SecretRepository) ListByUserAndType(ctx context.Context, userID string, secretType entity.SecretType) ([]entity.Secret, error) {
	query := `SELECT id, user_id, secret_type, encrypted_payload, created_at, updated_at
		FROM secrets WHERE user_id = ? AND secret_type = ? ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, userID, secretType)
	if err != nil {
		return nil, fmt.Errorf("query secrets: %w", err)
	}
	defer rows.Close()

	var secrets []entity.Secret
	for rows.Next() {
		var s entity.Secret
		if err := rows.Scan(&s.ID, &s.UserID, &s.SecretType, &s.EncryptedPayload, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

func (r *SecretRepository) ListByUser(ctx context.Context, userID string) ([]entity.Secret, error) {
	query := `SELECT id, user_id, secret_type, encrypted_payload, created_at, updated_at
		FROM secrets WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query secrets: %w", err)
	}
	defer rows.Close()

	var secrets []entity.Secret
	for rows.Next() {
		var s entity.Secret
		if err := rows.Scan(&s.ID, &s.UserID, &s.SecretType, &s.EncryptedPayload, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

func (r *SecretRepository) Update(ctx context.Context, secret entity.Secret) error {
	query := `UPDATE secrets SET encrypted_payload = ?, updated_at = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, secret.EncryptedPayload, secret.UpdatedAt, secret.ID)
	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	return nil
}

func (r *SecretRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}
