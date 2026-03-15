package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"secret-vault/internal/entity"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, session entity.Session) error {
	query := `INSERT INTO sessions (id, user_id, ip_address, user_agent, last_used_at, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.IPAddress, session.UserAgent,
		session.LastUsedAt, session.CreatedAt, session.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id string) (entity.Session, error) {
	query := `SELECT id, user_id, ip_address, user_agent, last_used_at, created_at, expires_at
		FROM sessions WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)

	var s entity.Session
	err := row.Scan(&s.ID, &s.UserID, &s.IPAddress, &s.UserAgent, &s.LastUsedAt, &s.CreatedAt, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.Session{}, entity.ErrSessionNotFound
	}
	if err != nil {
		return entity.Session{}, fmt.Errorf("scan session: %w", err)
	}
	return s, nil
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]entity.Session, error) {
	query := `SELECT id, user_id, ip_address, user_agent, last_used_at, created_at, expires_at
		FROM sessions WHERE user_id = ? ORDER BY last_used_at DESC`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			fmt.Printf("closing session rows: %v\n", err)
		}
	}()

	var sessions []entity.Session
	for rows.Next() {
		var s entity.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.IPAddress, &s.UserAgent, &s.LastUsedAt, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (r *SessionRepository) UpdateLastUsed(ctx context.Context, id string) error {
	query := `UPDATE sessions SET last_used_at = datetime('now') WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("update last_used: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteByID(ctx context.Context, id string) error {
	query := `DELETE FROM sessions WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteByUserIDExcept(ctx context.Context, userID, exceptSessionID string) error {
	query := `DELETE FROM sessions WHERE user_id = ? AND id != ?`
	_, err := r.db.ExecContext(ctx, query, userID, exceptSessionID)
	if err != nil {
		return fmt.Errorf("delete sessions except: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < datetime('now')`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}
