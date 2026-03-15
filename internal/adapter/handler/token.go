package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"secret-vault/internal/adapter/middleware"
	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
	"secret-vault/templates/pages"
)

type TokenHandler struct {
	tokens      *usecase.TokenUseCase
	auditLogger *usecase.AuditLogger
}

func NewTokenHandler(tokens *usecase.TokenUseCase, auditLogger *usecase.AuditLogger) *TokenHandler {
	return &TokenHandler{tokens: tokens, auditLogger: auditLogger}
}

func (h *TokenHandler) ListPage(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())

	tokens, err := h.tokens.List(r.Context(), userID, key)
	if err != nil {
		slog.Error("list tokens failed", "error", err)
		tokens = []usecase.TokenView{}
	}

	component := pages.Tokens(tokens, "")
	_ = component.Render(r.Context(), w)
}

func (h *TokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderList(w, r, "Invalid form data")
		return
	}

	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())

	payload := entity.TokenPayload{
		Title: r.FormValue("title"),
		Token: r.FormValue("token"),
		URL:   r.FormValue("url"),
		Note:  r.FormValue("note"),
	}

	_, err := h.tokens.Create(r.Context(), userID, key, payload)
	if err != nil {
		slog.Error("create token failed", "error", err)
		h.renderList(w, r, err.Error())
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionTokenCreated, entity.AuditCategoryToken, payload.Title, extractIP(r), r.UserAgent())

	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (h *TokenHandler) Update(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	secretID := chi.URLParam(r, "id")

	payload := entity.TokenPayload{
		Title: r.FormValue("title"),
		Token: r.FormValue("token"),
		URL:   r.FormValue("url"),
		Note:  r.FormValue("note"),
	}

	err := h.tokens.Update(r.Context(), userID, secretID, key, payload)
	if err != nil {
		slog.Error("update token failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionTokenUpdated, entity.AuditCategoryToken, payload.Title, extractIP(r), r.UserAgent())

	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (h *TokenHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	secretID := chi.URLParam(r, "id")

	err := h.tokens.Delete(r.Context(), userID, secretID)
	if err != nil {
		if errors.Is(err, entity.ErrSecretNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		slog.Error("delete token failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionTokenDeleted, entity.AuditCategoryToken, secretID[:8]+"...", extractIP(r), r.UserAgent())

	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (h *TokenHandler) renderList(w http.ResponseWriter, r *http.Request, errMsg string) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())

	tokens, err := h.tokens.List(r.Context(), userID, key)
	if err != nil {
		slog.Error("list tokens for re-render failed", "error", err)
		tokens = []usecase.TokenView{}
	}

	component := pages.Tokens(tokens, errMsg)
	_ = component.Render(r.Context(), w)
}
