package usecase

import (
	"context"

	"secret-vault/internal/entity"
)

type UserRepository interface {
	Create(ctx context.Context, user entity.User) error
	GetByUsername(ctx context.Context, username string) (entity.User, error)
	GetByID(ctx context.Context, id string) (entity.User, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
}

type SessionRepository interface {
	Create(ctx context.Context, session entity.Session) error
	GetByID(ctx context.Context, id string) (entity.Session, error)
	ListByUserID(ctx context.Context, userID string) ([]entity.Session, error)
	UpdateLastUsed(ctx context.Context, id string) error
	DeleteByID(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteByUserIDExcept(ctx context.Context, userID, exceptSessionID string) error
	DeleteExpired(ctx context.Context) error
}

type SecretRepository interface {
	Create(ctx context.Context, secret entity.Secret) error
	GetByID(ctx context.Context, id string) (entity.Secret, error)
	ListByUserAndType(ctx context.Context, userID string, secretType entity.SecretType) ([]entity.Secret, error)
	ListByUser(ctx context.Context, userID string) ([]entity.Secret, error)
	Update(ctx context.Context, secret entity.Secret) error
	Delete(ctx context.Context, id string) error
}

type AuditRepository interface {
	Create(ctx context.Context, log entity.AuditLog) error
	ListByUser(ctx context.Context, userID string, category string, limit, offset int) ([]entity.AuditLog, error)
	CountByUser(ctx context.Context, userID string, category string) (int, error)
	DeleteOlderThan(ctx context.Context, before string) error
}

type KeyStore interface {
	Set(sessionID string, key []byte)
	Get(sessionID string) ([]byte, bool)
	Delete(sessionID string)
	DeleteMany(sessionIDs []string)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) error
}

type KeyDeriver interface {
	DeriveKey(passphrase string, salt []byte) []byte
}

type MnemonicGenerator interface {
	Generate() (string, error)
}

type IDGenerator interface {
	NewID() string
}

type MnemonicHasher interface {
	HashForAuth(mnemonic string) string
}

type Encryptor interface {
	Encrypt(plaintext, key []byte) ([]byte, error)
	Decrypt(ciphertext, key []byte) ([]byte, error)
}
