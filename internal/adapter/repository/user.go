package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"secret-vault/internal/entity"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user entity.User) error {
	query := `INSERT INTO users (id, username, password_hash, key_salt, created_at) VALUES (?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, query, user.ID, user.Username, user.PasswordHash, user.KeySalt, user.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return entity.ErrUserExists
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (entity.User, error) {
	query := `SELECT id, username, password_hash, key_salt, created_at FROM users WHERE username = ?`
	row := r.db.QueryRowContext(ctx, query, username)

	var user entity.User
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.KeySalt, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.User{}, entity.ErrUserNotFound
	}
	if err != nil {
		return entity.User{}, fmt.Errorf("scan user: %w", err)
	}
	return user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (entity.User, error) {
	query := `SELECT id, username, password_hash, key_salt, created_at FROM users WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)

	var user entity.User
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.KeySalt, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.User{}, entity.ErrUserNotFound
	}
	if err != nil {
		return entity.User{}, fmt.Errorf("scan user: %w", err)
	}
	return user, nil
}

func (r *UserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT 1 FROM users WHERE username = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, query, username)

	var exists int
	err := row.Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}
	return true, nil
}

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
