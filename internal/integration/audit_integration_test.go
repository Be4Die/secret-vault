//go:build integration

package integration_test

import (
	"testing"

	"secret-vault/internal/entity"
)

func TestAudit_LogAndList(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, _, _ = registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	env.auditLogger.Log(ctx, user.ID, entity.AuditActionLogin, entity.AuditCategoryAuth, "Logged in", "1.1.1.1", "Chrome")
	env.auditLogger.Log(ctx, user.ID, entity.AuditActionCredentialCreated, entity.AuditCategoryCredential, "GitHub", "1.1.1.1", "Chrome")
	env.auditLogger.Log(ctx, user.ID, entity.AuditActionSearch, entity.AuditCategorySearch, "query: github", "1.1.1.1", "Chrome")

	page, err := env.auditUC.List(ctx, user.ID, "", 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 3 {
		t.Errorf("expected 3 total, got %d", page.Total)
	}
	if len(page.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(page.Entries))
	}

	// Filter by category
	authPage, err := env.auditUC.List(ctx, user.ID, "auth", 1)
	if err != nil {
		t.Fatalf("list auth: %v", err)
	}
	if authPage.Total != 1 {
		t.Errorf("expected 1 auth entry, got %d", authPage.Total)
	}
}

func TestAudit_Pagination(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, _, _ = registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	// Create 25 audit entries
	for i := 0; i < 25; i++ {
		env.auditLogger.Log(ctx, user.ID, entity.AuditActionLogin, entity.AuditCategoryAuth, "test", "1.1.1.1", "test")
	}

	page1, err := env.auditUC.List(ctx, user.ID, "", 1)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if page1.Page != 1 {
		t.Errorf("expected page 1, got %d", page1.Page)
	}
	if page1.TotalPages != 2 {
		t.Errorf("expected 2 pages, got %d", page1.TotalPages)
	}
	if len(page1.Entries) != 20 {
		t.Errorf("expected 20 entries on page 1, got %d", len(page1.Entries))
	}

	page2, err := env.auditUC.List(ctx, user.ID, "", 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2.Entries) != 5 {
		t.Errorf("expected 5 entries on page 2, got %d", len(page2.Entries))
	}
}

func TestAudit_IsolationBetweenUsers(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, _, _ = registerTestUser(t, env, "alice")
	_, _, _ = registerTestUser(t, env, "bobuser")

	alice, _ := env.userRepo.GetByUsername(ctx, "alice")
	bob, _ := env.userRepo.GetByUsername(ctx, "bobuser")

	env.auditLogger.Log(ctx, alice.ID, entity.AuditActionLogin, entity.AuditCategoryAuth, "alice login", "1.1.1.1", "test")

	bobPage, err := env.auditUC.List(ctx, bob.ID, "", 1)
	if err != nil {
		t.Fatalf("list bob: %v", err)
	}
	if bobPage.Total != 0 {
		t.Errorf("bob should have 0 audit entries, got %d", bobPage.Total)
	}
}
