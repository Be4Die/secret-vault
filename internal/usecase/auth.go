package usecase

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"secret-vault/internal/entity"
)

const (
	sessionDuration = 24 * time.Hour * 7
	keySaltSize     = 32
)

type AuthUseCase struct {
	users     UserRepository
	sessions  SessionRepository
	keyStore  KeyStore
	hasher    PasswordHasher
	deriver   KeyDeriver
	mnemonic  MnemonicGenerator
	idGen     IDGenerator
	mnemonicH MnemonicHasher
}

func NewAuthUseCase(
	users UserRepository,
	sessions SessionRepository,
	keyStore KeyStore,
	hasher PasswordHasher,
	deriver KeyDeriver,
	mnemonic MnemonicGenerator,
	idGen IDGenerator,
	mnemonicH MnemonicHasher,
) *AuthUseCase {
	return &AuthUseCase{
		users:     users,
		sessions:  sessions,
		keyStore:  keyStore,
		hasher:    hasher,
		deriver:   deriver,
		mnemonic:  mnemonic,
		idGen:     idGen,
		mnemonicH: mnemonicH,
	}
}

type PendingRegistration struct {
	Username string
	Mnemonic string
	Salt     []byte
}

func (uc *AuthUseCase) InitiateRegistration(ctx context.Context, username string) (*PendingRegistration, error) {
	username = strings.TrimSpace(strings.ToLower(username))

	user := entity.User{Username: username}
	if err := user.Validate(); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	exists, err := uc.users.ExistsByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("checking user exists: %w", err)
	}
	if exists {
		return nil, entity.ErrUserExists
	}

	mnemonic, err := uc.mnemonic.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating mnemonic: %w", err)
	}

	salt := make([]byte, keySaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	return &PendingRegistration{
		Username: username,
		Mnemonic: mnemonic,
		Salt:     salt,
	}, nil
}

func (uc *AuthUseCase) CompleteRegistration(ctx context.Context, pending *PendingRegistration, ip, userAgent string) (*entity.Session, error) {
	normalizedMnemonic := normalizeMnemonic(pending.Mnemonic)
	authHash := uc.mnemonicH.HashForAuth(normalizedMnemonic)

	hash, err := uc.hasher.Hash(authHash)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	user := entity.User{
		ID:           uc.idGen.NewID(),
		Username:     pending.Username,
		PasswordHash: hash,
		KeySalt:      pending.Salt,
		CreatedAt:    time.Now(),
	}

	if err := uc.users.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return uc.createSession(ctx, user.ID, normalizedMnemonic, pending.Salt, ip, userAgent)
}

func (uc *AuthUseCase) Login(ctx context.Context, username, mnemonic, ip, userAgent string) (*entity.Session, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	mnemonic = normalizeMnemonic(mnemonic)
	authHash := uc.mnemonicH.HashForAuth(mnemonic)

	user, err := uc.users.GetByUsername(ctx, username)
	if err != nil {
		return nil, entity.ErrInvalidCredentials
	}

	if err := uc.hasher.Compare(authHash, user.PasswordHash); err != nil {
		return nil, entity.ErrInvalidCredentials
	}

	return uc.createSession(ctx, user.ID, mnemonic, user.KeySalt, ip, userAgent)
}

func (uc *AuthUseCase) Logout(ctx context.Context, sessionID string) error {
	uc.keyStore.Delete(sessionID)
	return uc.sessions.DeleteByID(ctx, sessionID)
}

func (uc *AuthUseCase) GetSession(ctx context.Context, sessionID string) (*entity.Session, []byte, error) {
	session, err := uc.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return nil, nil, entity.ErrSessionNotFound
	}

	if session.IsExpired() {
		uc.keyStore.Delete(sessionID)
		_ = uc.sessions.DeleteByID(ctx, sessionID)
		return nil, nil, entity.ErrSessionExpired
	}

	key, ok := uc.keyStore.Get(sessionID)
	if !ok {
		_ = uc.sessions.DeleteByID(ctx, sessionID)
		return nil, nil, entity.ErrSessionNotFound
	}

	_ = uc.sessions.UpdateLastUsed(ctx, sessionID)

	return &session, key, nil
}

func (uc *AuthUseCase) GetUserByID(ctx context.Context, userID string) (entity.User, error) {
	return uc.users.GetByID(ctx, userID)
}

func (uc *AuthUseCase) VerifyMnemonic(ctx context.Context, userID, mnemonic string) error {
	mnemonic = normalizeMnemonic(mnemonic)
	authHash := uc.mnemonicH.HashForAuth(mnemonic)

	user, err := uc.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := uc.hasher.Compare(authHash, user.PasswordHash); err != nil {
		return entity.ErrInvalidCredentials
	}

	return nil
}

func (uc *AuthUseCase) createSession(ctx context.Context, userID, mnemonic string, salt []byte, ip, userAgent string) (*entity.Session, error) {
	now := time.Now()
	session := entity.Session{
		ID:         uc.idGen.NewID(),
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		LastUsedAt: now,
		CreatedAt:  now,
		ExpiresAt:  now.Add(sessionDuration),
	}

	if err := uc.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	encryptionKey := uc.deriver.DeriveKey(mnemonic, salt)
	uc.keyStore.Set(session.ID, encryptionKey)

	return &session, nil
}

func normalizeMnemonic(m string) string {
	words := strings.Fields(strings.ToLower(m))
	return strings.Join(words, " ")
}
