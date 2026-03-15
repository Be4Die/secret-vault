package handler

import (
	"log/slog"
	"net/http"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
	"secret-vault/templates/pages"
)

type AuthHandler struct {
	auth        *usecase.AuthUseCase
	auditLogger *usecase.AuditLogger
	pending     map[string]*usecase.PendingRegistration
}

func NewAuthHandler(auth *usecase.AuthUseCase, auditLogger *usecase.AuditLogger) *AuthHandler {
	return &AuthHandler{
		auth:        auth,
		auditLogger: auditLogger,
		pending:     make(map[string]*usecase.PendingRegistration),
	}
}

func (h *AuthHandler) ShowAuth(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "login"
	}
	component := pages.Auth(tab, "", "")
	_ = component.Render(r.Context(), w)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		component := pages.Auth("register", "Invalid form data", "")
		_ = component.Render(r.Context(), w)
		return
	}

	username := r.FormValue("username")

	pending, err := h.auth.InitiateRegistration(r.Context(), username)
	if err != nil {
		component := pages.Auth("register", err.Error(), "")
		_ = component.Render(r.Context(), w)
		return
	}

	h.pending[pending.Username] = pending

	component := pages.ShowSeed(pending.Mnemonic, pending.Username)
	_ = component.Render(r.Context(), w)
}

func (h *AuthHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		component := pages.Auth("register", "Invalid form data", "")
		_ = component.Render(r.Context(), w)
		return
	}

	token := r.FormValue("token")
	pending, ok := h.pending[token]
	if !ok {
		component := pages.Auth("register", "Registration expired, please try again", "")
		_ = component.Render(r.Context(), w)
		return
	}

	delete(h.pending, token)

	ip := extractIP(r)
	ua := r.UserAgent()

	session, err := h.auth.CompleteRegistration(r.Context(), pending, ip, ua)
	if err != nil {
		slog.Error("complete registration failed", "error", err)
		component := pages.Auth("register", "Registration failed: "+err.Error(), "")
		_ = component.Render(r.Context(), w)
		return
	}

	h.auditLogger.Log(r.Context(), session.UserID, entity.AuditActionRegister, entity.AuditCategoryAuth, "Account created", ip, ua)

	setSessionCookie(w, session.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		component := pages.Auth("login", "Invalid form data", "")
		_ = component.Render(r.Context(), w)
		return
	}

	username := r.FormValue("username")
	mnemonic := r.FormValue("mnemonic")
	ip := extractIP(r)
	ua := r.UserAgent()

	session, err := h.auth.Login(r.Context(), username, mnemonic, ip, ua)
	if err != nil {
		h.auditLogger.Log(r.Context(), "", entity.AuditActionLoginFailed, entity.AuditCategoryAuth, "Failed login for: "+username, ip, ua)
		component := pages.Auth("login", "Invalid username or seed phrase", "")
		_ = component.Render(r.Context(), w)
		return
	}

	h.auditLogger.Log(r.Context(), session.UserID, entity.AuditActionLogin, entity.AuditCategoryAuth, "Logged in", ip, ua)

	setSessionCookie(w, session.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	_ = h.auth.Logout(r.Context(), cookie.Value)
	clearSessionCookie(w)
	http.Redirect(w, r, "/auth", http.StatusSeeOther)
}
