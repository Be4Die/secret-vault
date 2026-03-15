package entity

import (
	"time"
)

type AuditAction string

const (
	AuditActionLogin             AuditAction = "login"
	AuditActionLoginFailed       AuditAction = "login_failed"
	AuditActionLogout            AuditAction = "logout"
	AuditActionRegister          AuditAction = "register"
	AuditActionSessionTerminated AuditAction = "session_terminated"
	AuditActionSessionsCleared   AuditAction = "sessions_cleared"

	AuditActionCredentialCreated AuditAction = "credential_created"
	AuditActionCredentialViewed  AuditAction = "credential_viewed"
	AuditActionCredentialUpdated AuditAction = "credential_updated"
	AuditActionCredentialDeleted AuditAction = "credential_deleted"

	AuditActionTokenCreated AuditAction = "token_created"
	AuditActionTokenUpdated AuditAction = "token_updated"
	AuditActionTokenDeleted AuditAction = "token_deleted"

	AuditActionExport AuditAction = "export"
	AuditActionImport AuditAction = "import"

	AuditActionSearch AuditAction = "search"
)

type AuditCategory string

const (
	AuditCategoryAuth       AuditCategory = "auth"
	AuditCategoryCredential AuditCategory = "credential"
	AuditCategoryToken      AuditCategory = "token"
	AuditCategoryData       AuditCategory = "data"
	AuditCategorySearch     AuditCategory = "search"
)

type AuditLog struct {
	ID        string
	UserID    string
	Action    AuditAction
	Category  AuditCategory
	Detail    string
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}
