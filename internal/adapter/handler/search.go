package handler

import (
	"log/slog"
	"net/http"

	"secret-vault/internal/adapter/middleware"
	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
	"secret-vault/templates/components"
)

type SearchHandler struct {
	search      *usecase.SearchUseCase
	credentials *usecase.CredentialUseCase
	tokens      *usecase.TokenUseCase
	auditLogger *usecase.AuditLogger
}

func NewSearchHandler(
	search *usecase.SearchUseCase,
	credentials *usecase.CredentialUseCase,
	tokens *usecase.TokenUseCase,
	auditLogger *usecase.AuditLogger,
) *SearchHandler {
	return &SearchHandler{
		search:      search,
		credentials: credentials,
		tokens:      tokens,
		auditLogger: auditLogger,
	}
}

func (h *SearchHandler) SearchCredentials(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	query := r.URL.Query().Get("q")

	if query == "" {
		creds, err := h.credentials.List(r.Context(), userID, key)
		if err != nil {
			slog.Error("list credentials failed", "error", err)
			creds = []usecase.CredentialView{}
		}
		component := components.CredentialList(creds)
		_ = component.Render(r.Context(), w)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionSearch, entity.AuditCategorySearch, "credentials: "+query, extractIP(r), r.UserAgent())

	results, err := h.search.SearchCredentials(r.Context(), userID, key, query)
	if err != nil {
		slog.Error("search credentials failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	component := components.CredentialList(results)
	_ = component.Render(r.Context(), w)
}

func (h *SearchHandler) SearchTokens(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	query := r.URL.Query().Get("q")

	if query == "" {
		tokens, err := h.tokens.List(r.Context(), userID, key)
		if err != nil {
			slog.Error("list tokens failed", "error", err)
			tokens = []usecase.TokenView{}
		}
		component := components.TokenList(tokens)
		_ = component.Render(r.Context(), w)
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionSearch, entity.AuditCategorySearch, "tokens: "+query, extractIP(r), r.UserAgent())

	results, err := h.search.SearchTokens(r.Context(), userID, key, query)
	if err != nil {
		slog.Error("search tokens failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	component := components.TokenList(results)
	_ = component.Render(r.Context(), w)
}

func (h *SearchHandler) SearchGlobal(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	key := middleware.GetEncryptionKey(r.Context())
	query := r.URL.Query().Get("q")

	if query == "" {
		return
	}

	h.auditLogger.Log(r.Context(), userID, entity.AuditActionSearch, entity.AuditCategorySearch, "global: "+query, extractIP(r), r.UserAgent())

	results, err := h.search.SearchGlobal(r.Context(), userID, key, query)
	if err != nil {
		slog.Error("global search failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	component := components.GlobalSearchResults(results)
	_ = component.Render(r.Context(), w)
}
