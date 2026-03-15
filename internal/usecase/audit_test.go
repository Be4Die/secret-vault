package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
)

func newAuditUseCase(audits *mockAuditRepository) *usecase.AuditUseCase {
	if audits == nil {
		audits = newMockAuditRepository()
	}
	return usecase.NewAuditUseCase(audits, newMockIDGenerator())
}

func TestAuditUseCase_List_Success(t *testing.T) {
	audits := newMockAuditRepository()
	now := time.Now()

	for i := 0; i < 25; i++ {
		audits.logs = append(audits.logs, entity.AuditLog{
			ID:        "log-" + string(rune('a'+i)),
			UserID:    "user1",
			Action:    entity.AuditActionLogin,
			Category:  entity.AuditCategoryAuth,
			CreatedAt: now,
		})
	}

	uc := newAuditUseCase(audits)

	page, err := uc.List(context.Background(), "user1", "", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if page.Total != 25 {
		t.Errorf("expected total 25, got %d", page.Total)
	}
	if page.Page != 1 {
		t.Errorf("expected page 1, got %d", page.Page)
	}
	if page.TotalPages != 2 {
		t.Errorf("expected 2 total pages, got %d", page.TotalPages)
	}
	if len(page.Entries) != 20 {
		t.Errorf("expected 20 entries on first page, got %d", len(page.Entries))
	}
}

func TestAuditUseCase_List_Page2(t *testing.T) {
	audits := newMockAuditRepository()
	now := time.Now()

	for i := 0; i < 25; i++ {
		audits.logs = append(audits.logs, entity.AuditLog{
			ID:        "log-" + string(rune('a'+i)),
			UserID:    "user1",
			Action:    entity.AuditActionLogin,
			Category:  entity.AuditCategoryAuth,
			CreatedAt: now,
		})
	}

	uc := newAuditUseCase(audits)

	page, err := uc.List(context.Background(), "user1", "", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if page.Page != 2 {
		t.Errorf("expected page 2, got %d", page.Page)
	}
	if len(page.Entries) != 5 {
		t.Errorf("expected 5 entries on second page, got %d", len(page.Entries))
	}
}

func TestAuditUseCase_List_WithCategory(t *testing.T) {
	audits := newMockAuditRepository()
	now := time.Now()

	audits.logs = append(audits.logs,
		entity.AuditLog{ID: "1", UserID: "user1", Action: entity.AuditActionLogin, Category: entity.AuditCategoryAuth, CreatedAt: now},
		entity.AuditLog{ID: "2", UserID: "user1", Action: entity.AuditActionCredentialCreated, Category: entity.AuditCategoryCredential, CreatedAt: now},
	)

	uc := newAuditUseCase(audits)

	page, err := uc.List(context.Background(), "user1", "auth", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if page.Total != 1 {
		t.Errorf("expected total 1, got %d", page.Total)
	}
}

func TestAuditUseCase_List_PageZero(t *testing.T) {
	audits := newMockAuditRepository()
	audits.logs = append(audits.logs, entity.AuditLog{
		ID: "1", UserID: "user1", Action: entity.AuditActionLogin,
		Category: entity.AuditCategoryAuth, CreatedAt: time.Now(),
	})

	uc := newAuditUseCase(audits)

	page, err := uc.List(context.Background(), "user1", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if page.Page != 1 {
		t.Errorf("expected page 1 (corrected from 0), got %d", page.Page)
	}
}

func TestAuditUseCase_List_PageBeyondMax(t *testing.T) {
	audits := newMockAuditRepository()
	audits.logs = append(audits.logs, entity.AuditLog{
		ID: "1", UserID: "user1", Action: entity.AuditActionLogin,
		Category: entity.AuditCategoryAuth, CreatedAt: time.Now(),
	})

	uc := newAuditUseCase(audits)

	page, err := uc.List(context.Background(), "user1", "", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if page.Page != 1 {
		t.Errorf("expected page 1 (corrected from 100), got %d", page.Page)
	}
}

func TestAuditUseCase_List_EmptyResult(t *testing.T) {
	uc := newAuditUseCase(nil)

	page, err := uc.List(context.Background(), "user1", "", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if page.Total != 0 {
		t.Errorf("expected total 0, got %d", page.Total)
	}
	if page.TotalPages != 1 {
		t.Errorf("expected 1 total page (minimum), got %d", page.TotalPages)
	}
}

func TestAuditUseCase_List_CountError(t *testing.T) {
	audits := newMockAuditRepository()
	audits.countByUserErr = errors.New("db error")

	uc := newAuditUseCase(audits)

	_, err := uc.List(context.Background(), "user1", "", 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditUseCase_List_ListError(t *testing.T) {
	audits := newMockAuditRepository()
	audits.countResult = 5
	audits.listByUserErr = errors.New("db error")

	uc := newAuditUseCase(audits)

	_, err := uc.List(context.Background(), "user1", "", 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditUseCase_Cleanup_Success(t *testing.T) {
	audits := newMockAuditRepository()
	uc := newAuditUseCase(audits)

	err := uc.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuditUseCase_Cleanup_Error(t *testing.T) {
	audits := newMockAuditRepository()
	audits.deleteOlderThanErr = errors.New("db error")

	uc := newAuditUseCase(audits)

	err := uc.Cleanup(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
