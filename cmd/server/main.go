package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"secret-vault/internal/adapter/handler"
	"secret-vault/internal/adapter/middleware"
	"secret-vault/internal/adapter/repository"
	"secret-vault/internal/infrastructure/config"
	"secret-vault/internal/infrastructure/crypto"
	"secret-vault/internal/infrastructure/database"
	"secret-vault/internal/infrastructure/router"
	"secret-vault/internal/infrastructure/search"
	"secret-vault/internal/infrastructure/session"
	"secret-vault/internal/usecase"
)

func main() {
	if err := run(); err != nil {
		slog.Error("application failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logLevel := slog.LevelInfo
	if cfg.Env == "dev" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	slog.Info("starting server", "env", cfg.Env, "port", cfg.Port)

	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			slog.Error("closing database", "error", err)
		}
	}()

	if err := database.Migrate(db, "migrations/init.sql"); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	slog.Info("database ready", "path", cfg.DatabasePath)

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	secretRepo := repository.NewSecretRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	keyStore := session.NewKeyStore()
	passwordHasher := crypto.NewPasswordHasher()
	keyDeriver := crypto.NewKeyDeriver()
	mnemonicGen := crypto.NewMnemonicGenerator()
	mnemonicHasher := crypto.NewMnemonicHasher()
	idGen := crypto.NewIDGenerator()
	encryptor := crypto.NewAESEncryptor()
	fuzzySearcher := search.NewFuzzySearcher()

	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		sessionRepo,
		keyStore,
		passwordHasher,
		keyDeriver,
		mnemonicGen,
		idGen,
		mnemonicHasher,
	)

	credentialUseCase := usecase.NewCredentialUseCase(
		secretRepo,
		encryptor,
		idGen,
	)

	tokenUseCase := usecase.NewTokenUseCase(
		secretRepo,
		encryptor,
		idGen,
	)

	searchUseCase := usecase.NewSearchUseCase(
		secretRepo,
		encryptor,
		fuzzySearcher,
	)

	accountUseCase := usecase.NewAccountUseCase(
		sessionRepo,
		secretRepo,
		keyStore,
		encryptor,
		idGen,
	)

	passwordUseCase := usecase.NewPasswordUseCase()

	auditUseCase := usecase.NewAuditUseCase(auditRepo, idGen)
	auditLogger := usecase.NewAuditLogger(auditRepo, idGen)

	authHandler := handler.NewAuthHandler(authUseCase, auditLogger)
	homeHandler := handler.NewHomeHandler()
	credentialHandler := handler.NewCredentialHandler(credentialUseCase, auditLogger)
	tokenHandler := handler.NewTokenHandler(tokenUseCase, auditLogger)
	searchHandler := handler.NewSearchHandler(searchUseCase, credentialUseCase, tokenUseCase, auditLogger)
	accountHandler := handler.NewAccountHandler(accountUseCase, auditUseCase, authUseCase, auditLogger)
	passwordHandler := handler.NewPasswordHandler(passwordUseCase)

	authMiddleware := middleware.NewAuthMiddleware(authUseCase)

	r := router.New(authHandler, homeHandler, credentialHandler, tokenHandler, searchHandler, accountHandler, passwordHandler, authMiddleware)

	addr := fmt.Sprintf(":%d", cfg.Port)
	slog.Info("listening", "addr", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
