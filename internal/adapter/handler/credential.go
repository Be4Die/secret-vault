package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"secret-vault/internal/adapter/middleware"
	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
	"secret-vault/templates/components"
	"secret-vault/templates/pages"
)

type CredentialHandler struct {
	credentials *usecase.CredentialUseCase
	auditLogger *usecase.AuditLogger
}

func NewCredentialHandler(credentials *usecase.CredentialUseCase, auditLogger *usecase.AuditLogger) *CredentialHandler {
	return &CredentialHandler{credentials: credentials, auditLogger: auditLogger}
}

func (h *CredentialHandler) ListPage(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())

	creds, err := h.credentials.List(r.Context(), userID, key)
	if err != nil {
		slog.Error("list credentials failed", "error", err)
		creds = []usecase.CredentialView{}
	}

	prefillPassword := r.URL.Query().Get("prefill_password")

	component := pages.Credentials(creds, "", prefillPassword)
	_ = component.Render(r.Context(), w)
}

func (h *CredentialHandler) Create(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderList(w, r, "Invalid form data")
		return
	}

	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())

	payload := entity.CredentialPayload{
		Title:    r.FormValue("title"),
		Login:    r.FormValue("login"),
		Password: r.FormValue("password"),
		URL:      r.FormValue("url"),
		Note:     r.FormValue("note"),
	}

	_, err := h.credentials.Create(r.Context(), userID, key, payload)
	if err != nil {
		slog.Error("create credential failed", "error", err)
		h.renderList(w, r, err.Error())
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionCredentialCreated, entity.AuditCategoryCredential, payload.Title, extractIP(r), r.UserAgent())

	http.Redirect(w, r, "/credentials", http.StatusSeeOther)
}

func (h *CredentialHandler) Detail(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	secretID := chi.URLParam(r, "id")

	cred, err := h.credentials.GetByID(r.Context(), userID, secretID, key)
	if err != nil {
		slog.Error("get credential failed", "error", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionCredentialViewed, entity.AuditCategoryCredential, cred.Payload.Title, extractIP(r), r.UserAgent())

	component := components.CredentialDetail(*cred)
	_ = component.Render(r.Context(), w)
}

func (h *CredentialHandler) Update(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	secretID := chi.URLParam(r, "id")

	payload := entity.CredentialPayload{
		Title:    r.FormValue("title"),
		Login:    r.FormValue("login"),
		Password: r.FormValue("password"),
		URL:      r.FormValue("url"),
		Note:     r.FormValue("note"),
	}

	err := h.credentials.Update(r.Context(), userID, secretID, key, payload)
	if err != nil {
		slog.Error("update credential failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionCredentialUpdated, entity.AuditCategoryCredential, payload.Title, extractIP(r), r.UserAgent())

	http.Redirect(w, r, "/credentials", http.StatusSeeOther)
}

func (h *CredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	secretID := chi.URLParam(r, "id")

	err := h.credentials.Delete(r.Context(), userID, secretID)
	if err != nil {
		if errors.Is(err, entity.ErrSecretNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		slog.Error("delete credential failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionCredentialDeleted, entity.AuditCategoryCredential, secretID[:8]+"...", extractIP(r), r.UserAgent())

	http.Redirect(w, r, "/credentials", http.StatusSeeOther)
}

func (h *CredentialHandler) renderList(w http.ResponseWriter, r *http.Request, errMsg string) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())

	creds, err := h.credentials.List(r.Context(), userID, key)
	if err != nil {
		slog.Error("list credentials for re-render failed", "error", err)
		creds = []usecase.CredentialView{}
	}

	component := pages.Credentials(creds, errMsg, "")
	_ = component.Render(r.Context(), w)
}
