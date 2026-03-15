package usecase

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"secret-vault/internal/entity"
)

type AccountUseCase struct {
	sessions  SessionRepository
	secrets   SecretRepository
	keyStore  KeyStore
	encryptor Encryptor
	idGen     IDGenerator
}

func NewAccountUseCase(
	sessions SessionRepository,
	secrets SecretRepository,
	keyStore KeyStore,
	encryptor Encryptor,
	idGen IDGenerator,
) *AccountUseCase {
	return &AccountUseCase{
		sessions:  sessions,
		secrets:   secrets,
		keyStore:  keyStore,
		encryptor: encryptor,
		idGen:     idGen,
	}
}

type SessionView struct {
	ID         string
	IPAddress  string
	UserAgent  string
	LastUsedAt time.Time
	CreatedAt  time.Time
	ExpiresAt  time.Time
	IsCurrent  bool
}

func (uc *AccountUseCase) ListSessions(ctx context.Context, userID, currentSessionID string) ([]SessionView, error) {
	sessions, err := uc.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	views := make([]SessionView, 0, len(sessions))
	for _, s := range sessions {
		if s.IsExpired() {
			continue
		}
		views = append(views, SessionView{
			ID:         s.ID,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			LastUsedAt: s.LastUsedAt,
			CreatedAt:  s.CreatedAt,
			ExpiresAt:  s.ExpiresAt,
			IsCurrent:  s.ID == currentSessionID,
		})
	}

	return views, nil
}

func (uc *AccountUseCase) TerminateSession(ctx context.Context, userID, sessionID, currentSessionID string) error {
	if sessionID == currentSessionID {
		return entity.ErrCurrentSession
	}

	session, err := uc.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.UserID != userID {
		return entity.ErrAccessDenied
	}

	uc.keyStore.Delete(sessionID)
	return uc.sessions.DeleteByID(ctx, sessionID)
}

func (uc *AccountUseCase) TerminateOtherSessions(ctx context.Context, userID, currentSessionID string) error {
	sessions, err := uc.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("listing sessions: %w", err)
	}

	var toDelete []string
	for _, s := range sessions {
		if s.ID != currentSessionID {
			toDelete = append(toDelete, s.ID)
		}
	}

	if len(toDelete) > 0 {
		uc.keyStore.DeleteMany(toDelete)
	}

	return uc.sessions.DeleteByUserIDExcept(ctx, userID, currentSessionID)
}

type ExportType string

const (
	ExportAll         ExportType = "all"
	ExportCredentials ExportType = "credentials"
	ExportTokens      ExportType = "tokens"
)

func (uc *AccountUseCase) Export(ctx context.Context, userID string, key []byte, exportType ExportType) ([]byte, string, error) {
	var secrets []entity.Secret
	var err error
	var filename string

	switch exportType {
	case ExportCredentials:
		secrets, err = uc.secrets.ListByUserAndType(ctx, userID, entity.SecretTypeCredential)
		filename = "credentials_export.csv.enc"
	case ExportTokens:
		secrets, err = uc.secrets.ListByUserAndType(ctx, userID, entity.SecretTypeToken)
		filename = "tokens_export.csv.enc"
	default:
		secrets, err = uc.secrets.ListByUser(ctx, userID)
		filename = "vault_export.csv.enc"
	}

	if err != nil {
		return nil, "", fmt.Errorf("listing secrets: %w", err)
	}

	csvData, err := uc.secretsToCSV(secrets, key)
	if err != nil {
		return nil, "", fmt.Errorf("generating CSV: %w", err)
	}

	encrypted, err := uc.encryptor.Encrypt(csvData, key)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting export: %w", err)
	}

	return encrypted, filename, nil
}

func (uc *AccountUseCase) Import(ctx context.Context, userID string, key []byte, data []byte) (int, error) {
	decrypted, err := uc.encryptor.Decrypt(data, key)
	if err != nil {
		return 0, fmt.Errorf("decrypting import: %w", err)
	}

	reader := csv.NewReader(bytes.NewReader(decrypted))

	header, err := reader.Read()
	if err != nil {
		return 0, fmt.Errorf("reading CSV header: %w", err)
	}

	if len(header) < 2 || header[0] != "type" {
		return 0, fmt.Errorf("invalid CSV format")
	}

	count := 0
	now := time.Now()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("reading CSV row: %w", err)
		}

		secret, err := uc.csvRowToSecret(record, header, userID, key, now)
		if err != nil {
			continue
		}

		if err := uc.secrets.Create(ctx, secret); err != nil {
			return count, fmt.Errorf("creating secret: %w", err)
		}
		count++
	}

	return count, nil
}

func (uc *AccountUseCase) secretsToCSV(secrets []entity.Secret, key []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	header := []string{"type", "title", "login", "password", "token", "url", "note"}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	for _, s := range secrets {
		decrypted, err := uc.encryptor.Decrypt(s.EncryptedPayload, key)
		if err != nil {
			return nil, fmt.Errorf("decrypting secret %s: %w", s.ID, err)
		}

		row, err := uc.decryptedToCSVRow(s.SecretType, decrypted)
		if err != nil {
			return nil, err
		}

		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return buf.Bytes(), writer.Error()
}

func (uc *AccountUseCase) decryptedToCSVRow(secretType entity.SecretType, data []byte) ([]string, error) {
	switch secretType {
	case entity.SecretTypeCredential:
		var p entity.CredentialPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, err
		}
		return []string{string(secretType), p.Title, p.Login, p.Password, "", p.URL, p.Note}, nil

	case entity.SecretTypeToken:
		var p entity.TokenPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, err
		}
		return []string{string(secretType), p.Title, "", "", p.Token, p.URL, p.Note}, nil

	default:
		return nil, fmt.Errorf("unknown secret type: %s", secretType)
	}
}

func (uc *AccountUseCase) csvRowToSecret(record, header []string, userID string, key []byte, now time.Time) (entity.Secret, error) {
	if len(record) < len(header) {
		return entity.Secret{}, fmt.Errorf("row too short")
	}

	fields := make(map[string]string)
	for i, h := range header {
		if i < len(record) {
			fields[h] = record[i]
		}
	}

	secretType := entity.SecretType(fields["type"])
	var payload []byte
	var err error

	switch secretType {
	case entity.SecretTypeCredential:
		p := entity.CredentialPayload{
			Title:    fields["title"],
			Login:    fields["login"],
			Password: fields["password"],
			URL:      fields["url"],
			Note:     fields["note"],
		}
		if vErr := p.Validate(); vErr != nil {
			return entity.Secret{}, vErr
		}
		payload, err = json.Marshal(p)

	case entity.SecretTypeToken:
		p := entity.TokenPayload{
			Title: fields["title"],
			Token: fields["token"],
			URL:   fields["url"],
			Note:  fields["note"],
		}
		if vErr := p.Validate(); vErr != nil {
			return entity.Secret{}, vErr
		}
		payload, err = json.Marshal(p)

	default:
		return entity.Secret{}, fmt.Errorf("unknown type: %s", fields["type"])
	}

	if err != nil {
		return entity.Secret{}, err
	}

	encrypted, err := uc.encryptor.Encrypt(payload, key)
	if err != nil {
		return entity.Secret{}, err
	}

	return entity.Secret{
		ID:               uc.idGen.NewID(),
		UserID:           userID,
		SecretType:       secretType,
		EncryptedPayload: encrypted,
		CreatedAt:        now,
		UpdatedAt:        now,
	}, nil
}

func ParseUserAgent(ua string) string {
	ua = strings.ToLower(ua)

	browser := "Unknown Browser"
	switch {
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "opr") || strings.Contains(ua, "opera"):
		browser = "Opera"
	case strings.Contains(ua, "edg"):
		browser = "Edge"
	case strings.Contains(ua, "chrome"):
		browser = "Chrome"
	case strings.Contains(ua, "safari"):
		browser = "Safari"
	}

	os := "Unknown OS"
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac os"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	}

	return browser + " on " + os
}
