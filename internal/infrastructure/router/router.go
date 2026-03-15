package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"

	"secret-vault/internal/adapter/handler"
	"secret-vault/internal/adapter/middleware"
)

func New(
	authHandler *handler.AuthHandler,
	homeHandler *handler.HomeHandler,
	credentialHandler *handler.CredentialHandler,
	tokenHandler *handler.TokenHandler,
	searchHandler *handler.SearchHandler,
	accountHandler *handler.AccountHandler,
	passwordHandler *handler.PasswordHandler,
	authMiddleware *middleware.AuthMiddleware,
) http.Handler {
	r := chi.NewRouter()

	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RequestID)
	r.Use(middleware.MethodOverride)

	fileServer := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	authLimiter := middleware.NewRateLimiter(10, time.Minute)

	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.RedirectIfAuth)
		r.Use(authLimiter.Limit)

		r.Get("/auth", authHandler.ShowAuth)
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/register/confirm", authHandler.ConfirmRegistration)
		r.Post("/auth/login", authHandler.Login)
	})

	r.Post("/auth/logout", authHandler.Logout)

	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.RequireAuth)

		r.Get("/", homeHandler.Show)

		r.Get("/credentials", credentialHandler.ListPage)
		r.Post("/credentials", credentialHandler.Create)
		r.Get("/credentials/{id}", credentialHandler.Detail)
		r.Post("/credentials/{id}", credentialHandler.Update)
		r.Delete("/credentials/{id}", credentialHandler.Delete)

		r.Get("/tokens", tokenHandler.ListPage)
		r.Post("/tokens", tokenHandler.Create)
		r.Post("/tokens/{id}", tokenHandler.Update)
		r.Delete("/tokens/{id}", tokenHandler.Delete)

		r.Get("/password-generator", passwordHandler.ShowPage)
		r.Post("/password-generator/generate", passwordHandler.Generate)

		r.Get("/account", accountHandler.Show)
		r.Post("/account/sessions/terminate", accountHandler.TerminateSession)
		r.Post("/account/sessions/terminate-others", accountHandler.TerminateOtherSessions)
		r.Post("/account/export", accountHandler.Export)
		r.Post("/account/import", accountHandler.Import)

		r.Get("/api/search/credentials", searchHandler.SearchCredentials)
		r.Get("/api/search/tokens", searchHandler.SearchTokens)
		r.Get("/api/search/global", searchHandler.SearchGlobal)
	})

	return r
}
