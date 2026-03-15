package usecase

import (
	"context"
	"log/slog"
	"time"

	"secret-vault/internal/entity"
)

type AuditLogger struct {
	audits AuditRepository
	idGen  IDGenerator
}

func NewAuditLogger(audits AuditRepository, idGen IDGenerator) *AuditLogger {
	return &AuditLogger{audits: audits, idGen: idGen}
}

func (l *AuditLogger) Log(ctx context.Context, userID string, action entity.AuditAction, category entity.AuditCategory, detail, ip, ua string) {
	log := entity.AuditLog{
		ID:        l.idGen.NewID(),
		UserID:    userID,
		Action:    action,
		Category:  category,
		Detail:    detail,
		IPAddress: ip,
		UserAgent: ua,
		CreatedAt: time.Now(),
	}

	if err := l.audits.Create(ctx, log); err != nil {
		slog.Error("failed to write audit log", "error", err, "action", action)
	}
}
