package middleware

import (
	"context"
	"net/http"

	"secret-vault/internal/usecase"
)

type contextKey string

const (
	userIDKey       contextKey = "user_id"
	sessionIDKey    contextKey = "session_id"
	encryptionKeyID contextKey = "encryption_key"
)

type AuthMiddleware struct {
	auth *usecase.AuthUseCase
}

func NewAuthMiddleware(auth *usecase.AuthUseCase) *AuthMiddleware {
	return &AuthMiddleware{auth: auth}
}

func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}

		session, key, err := m.auth.GetSession(r.Context(), cookie.Value)
		if err != nil {
			http.SetCookie(w, &http.Cookie{
				Name:   "session_id",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, session.UserID)
		ctx = context.WithValue(ctx, sessionIDKey, session.ID)
		ctx = context.WithValue(ctx, encryptionKeyID, key)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) RedirectIfAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		_, _, err = m.auth.GetSession(r.Context(), cookie.Value)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func GetUserID(ctx context.Context) string {
	val, _ := ctx.Value(userIDKey).(string)
	return val
}

func GetSessionID(ctx context.Context) string {
	val, _ := ctx.Value(sessionIDKey).(string)
	return val
}

func GetEncryptionKey(ctx context.Context) []byte {
	val, _ := ctx.Value(encryptionKeyID).([]byte)
	return val
}
