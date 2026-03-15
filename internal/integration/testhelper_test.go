//go:build integration

package integration_test

import (
	"database/sql"
	"os"
	"testing"

	"secret-vault/internal/adapter/repository"
	"secret-vault/internal/infrastructure/crypto"
	"secret-vault/internal/infrastructure/search"
	"secret-vault/internal/infrastructure/session"
	"secret-vault/internal/usecase"

	_ "modernc.org/sqlite"
)

type testEnv struct {
	db             *sql.DB
	userRepo       *repository.UserRepository
	sessionRepo    *repository.SessionRepository
	secretRepo     *repository.SecretRepository
	auditRepo      *repository.AuditRepository
	keyStore       *session.KeyStore
	encryptor      *crypto.AESEncryptor
	hasher         *crypto.PasswordHasher
	deriver        *crypto.KeyDeriver
	mnemonicGen    *crypto.MnemonicGenerator
	mnemonicHasher *crypto.MnemonicHasher
	idGen          *crypto.IDGenerator
	fuzzySearcher  *search.FuzzySearcher
	authUC         *usecase.AuthUseCase
	credentialUC   *usecase.CredentialUseCase
	tokenUC        *usecase.TokenUseCase
	searchUC       *usecase.SearchUseCase
	accountUC      *usecase.AccountUseCase
	auditUC        *usecase.AuditUseCase
	auditLogger    *usecase.AuditLogger
	passwordUC     *usecase.PasswordUseCase
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("foreign keys: %v", err)
	}

	migration, err := os.ReadFile("../../migrations/init.sql")
	if err != nil {
		t.Fatalf("reading migration: %v", err)
	}
	if _, err := db.Exec(string(migration)); err != nil {
		t.Fatalf("running migration: %v", err)
	}

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	secretRepo := repository.NewSecretRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	keyStore := session.NewKeyStore()
	encryptor := crypto.NewAESEncryptor()
	hasher := crypto.NewPasswordHasher()
	deriver := crypto.NewKeyDeriver()
	mnemonicGen := crypto.NewMnemonicGenerator()
	mnemonicHasher := crypto.NewMnemonicHasher()
	idGen := crypto.NewIDGenerator()
	fuzzySearcher := search.NewFuzzySearcher()

	authUC := usecase.NewAuthUseCase(userRepo, sessionRepo, keyStore, hasher, deriver, mnemonicGen, idGen, mnemonicHasher)
	credentialUC := usecase.NewCredentialUseCase(secretRepo, encryptor, idGen)
	tokenUC := usecase.NewTokenUseCase(secretRepo, encryptor, idGen)
	searchUC := usecase.NewSearchUseCase(secretRepo, encryptor, fuzzySearcher)
	accountUC := usecase.NewAccountUseCase(sessionRepo, secretRepo, keyStore, encryptor, idGen)
	auditUC := usecase.NewAuditUseCase(auditRepo, idGen)
	auditLogger := usecase.NewAuditLogger(auditRepo, idGen)
	passwordUC := usecase.NewPasswordUseCase()

	return &testEnv{
		db: db, userRepo: userRepo, sessionRepo: sessionRepo,
		secretRepo: secretRepo, auditRepo: auditRepo,
		keyStore: keyStore, encryptor: encryptor, hasher: hasher,
		deriver: deriver, mnemonicGen: mnemonicGen, mnemonicHasher: mnemonicHasher,
		idGen: idGen, fuzzySearcher: fuzzySearcher,
		authUC: authUC, credentialUC: credentialUC, tokenUC: tokenUC,
		searchUC: searchUC, accountUC: accountUC, auditUC: auditUC,
		auditLogger: auditLogger, passwordUC: passwordUC,
	}
}

// registerTestUser creates a user through the full auth flow and returns session + encryption key.
func registerTestUser(t *testing.T, env *testEnv, username string) (sessionID string, encKey []byte, mnemonic string) {
	t.Helper()

	pending, err := env.authUC.InitiateRegistration(t.Context(), username)
	if err != nil {
		t.Fatalf("initiate registration: %v", err)
	}

	sess, err := env.authUC.CompleteRegistration(t.Context(), pending, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("complete registration: %v", err)
	}

	key, ok := env.keyStore.Get(sess.ID)
	if !ok {
		t.Fatal("encryption key not found in key store")
	}

	return sess.ID, key, pending.Mnemonic
}
