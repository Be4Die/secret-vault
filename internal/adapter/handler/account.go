package handler

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"secret-vault/internal/adapter/middleware"
	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
	"secret-vault/templates/pages"
)

type AccountHandler struct {
	account     *usecase.AccountUseCase
	audit       *usecase.AuditUseCase
	auth        *usecase.AuthUseCase
	auditLogger *usecase.AuditLogger
}

func NewAccountHandler(
	account *usecase.AccountUseCase,
	audit *usecase.AuditUseCase,
	auth *usecase.AuthUseCase,
	auditLogger *usecase.AuditLogger,
) *AccountHandler {
	return &AccountHandler{
		account:     account,
		audit:       audit,
		auth:        auth,
		auditLogger: auditLogger,
	}
}

func (h *AccountHandler) Show(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())

	sessions, err := h.account.ListSessions(r.Context(), userID, sessionID)
	if err != nil {
		slog.Error("list sessions failed", "error", err)
		sessions = []usecase.SessionView{}
	}

	category := r.URL.Query().Get("category")
	pageStr := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}

	auditPage, err := h.audit.List(r.Context(), userID, category, page)
	if err != nil {
		slog.Error("list audit logs failed", "error", err)
		auditPage = &usecase.AuditPage{
			Entries:    []usecase.AuditEntry{},
			Total:      0,
			Page:       1,
			PageSize:   20,
			TotalPages: 1,
		}
	}

	user, err := h.auth.GetUserByID(r.Context(), userID)
	if err != nil {
		slog.Error("get user failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	component := pages.Account(pages.AccountPageData{
		Username: user.Username,
		Sessions: sessions,
		Audit:    auditPage,
		Category: category,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AccountHandler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	ip := extractIP(r)
	ua := r.UserAgent()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	targetID := r.FormValue("session_id")

	if err := h.account.TerminateSession(r.Context(), userID, targetID, sessionID); err != nil {
		slog.Error("terminate session failed", "error", err)
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionSessionTerminated, entity.AuditCategoryAuth, "Terminated session: "+targetID[:8]+"...", ip, ua)

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (h *AccountHandler) TerminateOtherSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	sessionID := middleware.GetSessionID(r.Context())
	ip := extractIP(r)
	ua := r.UserAgent()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	mnemonic := r.FormValue("mnemonic")
	if err := h.auth.VerifyMnemonic(r.Context(), userID, mnemonic); err != nil {
		http.Redirect(w, r, "/account?error=invalid_mnemonic", http.StatusSeeOther)
		return
	}

	if err := h.account.TerminateOtherSessions(r.Context(), userID, sessionID); err != nil {
		slog.Error("terminate other sessions failed", "error", err)
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionSessionsCleared, entity.AuditCategoryAuth, "Terminated all other sessions", ip, ua)

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (h *AccountHandler) Export(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	ip := extractIP(r)
	ua := r.UserAgent()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	mnemonic := r.FormValue("mnemonic")
	if err := h.auth.VerifyMnemonic(r.Context(), userID, mnemonic); err != nil {
		http.Redirect(w, r, "/account?error=invalid_mnemonic", http.StatusSeeOther)
		return
	}

	exportType := usecase.ExportType(r.FormValue("export_type"))
	switch exportType {
	case usecase.ExportAll, usecase.ExportCredentials, usecase.ExportTokens:
	default:
		exportType = usecase.ExportAll
	}

	data, filename, err := h.account.Export(r.Context(), userID, key, exportType)
	if err != nil {
		slog.Error("export failed", "error", err)
		http.Redirect(w, r, "/account?error=export_failed", http.StatusSeeOther)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionExport, entity.AuditCategoryData, fmt.Sprintf("Exported: %s", exportType), ip, ua)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (h *AccountHandler) Import(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	ip := extractIP(r)
	ua := r.UserAgent()

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Redirect(w, r, "/account?error=invalid_form", http.StatusSeeOther)
		return
	}

	mnemonic := r.FormValue("mnemonic")
	if err := h.auth.VerifyMnemonic(r.Context(), userID, mnemonic); err != nil {
		http.Redirect(w, r, "/account?error=invalid_mnemonic", http.StatusSeeOther)
		return
	}

	file, _, err := r.FormFile("import_file")
	if err != nil {
		http.Redirect(w, r, "/account?error=no_file", http.StatusSeeOther)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/account?error=read_failed", http.StatusSeeOther)
		return
	}

	count, err := h.account.Import(r.Context(), userID, key, data)
	if err != nil {
		slog.Error("import failed", "error", err)
		http.Redirect(w, r, "/account?error=import_failed", http.StatusSeeOther)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionImport, entity.AuditCategoryData, fmt.Sprintf("Imported %d secrets", count), ip, ua)

	http.Redirect(w, r, fmt.Sprintf("/account?success=imported_%d", count), http.StatusSeeOther)
}
