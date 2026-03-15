package repository

import (
	"context"
	"database/sql"
	"fmt"

	"secret-vault/internal/entity"
)

type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Create(ctx context.Context, log entity.AuditLog) error {
	query := `INSERT INTO audit_logs (id, user_id, action, category, detail, ip_address, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.Action, log.Category,
		log.Detail, log.IPAddress, log.UserAgent, log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

func (r *AuditRepository) ListByUser(ctx context.Context, userID string, category string, limit, offset int) ([]entity.AuditLog, error) {
	var rows *sql.Rows
	var err error

	if category != "" {
		query := `SELECT id, user_id, action, category, detail, ip_address, user_agent, created_at
			FROM audit_logs WHERE user_id = ? AND category = ?
			ORDER BY created_at DESC LIMIT ? OFFSET ?`
		rows, err = r.db.QueryContext(ctx, query, userID, category, limit, offset)
	} else {
		query := `SELECT id, user_id, action, category, detail, ip_address, user_agent, created_at
			FROM audit_logs WHERE user_id = ?
			ORDER BY created_at DESC LIMIT ? OFFSET ?`
		rows, err = r.db.QueryContext(ctx, query, userID, limit, offset)
	}

	if err != nil {
		return nil, fmt.Errorf("query audit logs: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			fmt.Printf("closing audit rows: %v\n", err)
		}
	}()

	var logs []entity.AuditLog
	for rows.Next() {
		var l entity.AuditLog
		if err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.Category, &l.Detail, &l.IPAddress, &l.UserAgent, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func (r *AuditRepository) CountByUser(ctx context.Context, userID string, category string) (int, error) {
	var count int
	var err error

	if category != "" {
		err = r.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_logs WHERE user_id = ? AND category = ?`,
			userID, category,
		).Scan(&count)
	} else {
		err = r.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_logs WHERE user_id = ?`,
			userID,
		).Scan(&count)
	}

	if err != nil {
		return 0, fmt.Errorf("count audit logs: %w", err)
	}
	return count, nil
}

func (r *AuditRepository) DeleteOlderThan(ctx context.Context, before string) error {
	query := `DELETE FROM audit_logs WHERE created_at < ?`
	_, err := r.db.ExecContext(ctx, query, before)
	if err != nil {
		return fmt.Errorf("delete old audit logs: %w", err)
	}
	return nil
}
