package usecase_test

import (
	"context"
	"errors"
	"testing"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func TestAuditLogger_Log_Success(t *testing.T) {
	audits := newMockAuditRepository()
	logger := usecase.NewAuditLogger(audits, newMockIDGenerator())

	logger.Log(
		context.Background(),
		"user1",
		entity.AuditActionLogin,
		entity.AuditCategoryAuth,
		"logged in",
		"1.2.3.4",
		"Chrome",
	)

	if len(audits.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(audits.logs))
	}

	log := audits.logs[0]
	if log.UserID != "user1" {
		t.Errorf("expected userID 'user1', got %q", log.UserID)
	}
	if log.Action != entity.AuditActionLogin {
		t.Errorf("expected action 'login', got %q", log.Action)
	}
	if log.Category != entity.AuditCategoryAuth {
		t.Errorf("expected category 'auth', got %q", log.Category)
	}
	if log.Detail != "logged in" {
		t.Errorf("expected detail 'logged in', got %q", log.Detail)
	}
	if log.IPAddress != "1.2.3.4" {
		t.Errorf("expected IP '1.2.3.4', got %q", log.IPAddress)
	}
	if log.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestAuditLogger_Log_RepoError(t *testing.T) {
	audits := newMockAuditRepository()
	audits.createErr = errors.New("db error")
	logger := usecase.NewAuditLogger(audits, newMockIDGenerator())

	// Should not panic, just log error via slog
	logger.Log(
		context.Background(),
		"user1",
		entity.AuditActionLogin,
		entity.AuditCategoryAuth,
		"logged in",
		"1.2.3.4",
		"Chrome",
	)

	// No logs should be stored due to error
	if len(audits.logs) != 0 {
		t.Errorf("expected 0 logs (create failed), got %d", len(audits.logs))
	}
}
