package usecase_test

import (
	"context"
	"fmt"
	"sync"

	"secret-vault/internal/entity"
)

// --- UserRepository mock ---

type mockUserRepository struct {
	users            map[string]entity.User // keyed by ID
	byName           map[string]entity.User // keyed by username
	createErr        error
	getByUsernameErr error
	getByIDErr       error
	existsErr        error
}

func newMockUserRepository() *mockUserRepository {
	return &mockUserRepository{
		users:  make(map[string]entity.User),
		byName: make(map[string]entity.User),
	}
}

func (m *mockUserRepository) Create(_ context.Context, user entity.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.users[user.ID] = user
	m.byName[user.Username] = user
	return nil
}

func (m *mockUserRepository) GetByUsername(_ context.Context, username string) (entity.User, error) {
	if m.getByUsernameErr != nil {
		return entity.User{}, m.getByUsernameErr
	}
	u, ok := m.byName[username]
	if !ok {
		return entity.User{}, entity.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepository) GetByID(_ context.Context, id string) (entity.User, error) {
	if m.getByIDErr != nil {
		return entity.User{}, m.getByIDErr
	}
	u, ok := m.users[id]
	if !ok {
		return entity.User{}, entity.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepository) ExistsByUsername(_ context.Context, username string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	_, ok := m.byName[username]
	return ok, nil
}

// --- SessionRepository mock ---

type mockSessionRepository struct {
	sessions                map[string]entity.Session
	createErr               error
	getByIDErr              error
	deleteByIDErr           error
	deleteByUserIDErr       error
	deleteByUserIDExceptErr error
	deleteExpiredErr        error
	updateLastUsedErr       error
	listByUserIDErr         error
}

func newMockSessionRepository() *mockSessionRepository {
	return &mockSessionRepository{
		sessions: make(map[string]entity.Session),
	}
}

func (m *mockSessionRepository) Create(_ context.Context, session entity.Session) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionRepository) GetByID(_ context.Context, id string) (entity.Session, error) {
	if m.getByIDErr != nil {
		return entity.Session{}, m.getByIDErr
	}
	s, ok := m.sessions[id]
	if !ok {
		return entity.Session{}, entity.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockSessionRepository) ListByUserID(_ context.Context, userID string) ([]entity.Session, error) {
	if m.listByUserIDErr != nil {
		return nil, m.listByUserIDErr
	}
	var result []entity.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockSessionRepository) UpdateLastUsed(_ context.Context, _ string) error {
	return m.updateLastUsedErr
}

func (m *mockSessionRepository) DeleteByID(_ context.Context, id string) error {
	if m.deleteByIDErr != nil {
		return m.deleteByIDErr
	}
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionRepository) DeleteByUserID(_ context.Context, userID string) error {
	if m.deleteByUserIDErr != nil {
		return m.deleteByUserIDErr
	}
	for id, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockSessionRepository) DeleteByUserIDExcept(_ context.Context, userID, exceptSessionID string) error {
	if m.deleteByUserIDExceptErr != nil {
		return m.deleteByUserIDExceptErr
	}
	for id, s := range m.sessions {
		if s.UserID == userID && id != exceptSessionID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockSessionRepository) DeleteExpired(_ context.Context) error {
	return m.deleteExpiredErr
}

// --- SecretRepository mock ---

type mockSecretRepository struct {
	secrets              map[string]entity.Secret
	createErr            error
	getByIDErr           error
	listByUserAndTypeErr error
	listByUserErr        error
	updateErr            error
	deleteErr            error
}

func newMockSecretRepository() *mockSecretRepository {
	return &mockSecretRepository{
		secrets: make(map[string]entity.Secret),
	}
}

func (m *mockSecretRepository) Create(_ context.Context, secret entity.Secret) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.secrets[secret.ID] = secret
	return nil
}

func (m *mockSecretRepository) GetByID(_ context.Context, id string) (entity.Secret, error) {
	if m.getByIDErr != nil {
		return entity.Secret{}, m.getByIDErr
	}
	s, ok := m.secrets[id]
	if !ok {
		return entity.Secret{}, entity.ErrSecretNotFound
	}
	return s, nil
}

func (m *mockSecretRepository) ListByUserAndType(_ context.Context, userID string, secretType entity.SecretType) ([]entity.Secret, error) {
	if m.listByUserAndTypeErr != nil {
		return nil, m.listByUserAndTypeErr
	}
	var result []entity.Secret
	for _, s := range m.secrets {
		if s.UserID == userID && s.SecretType == secretType {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockSecretRepository) ListByUser(_ context.Context, userID string) ([]entity.Secret, error) {
	if m.listByUserErr != nil {
		return nil, m.listByUserErr
	}
	var result []entity.Secret
	for _, s := range m.secrets {
		if s.UserID == userID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockSecretRepository) Update(_ context.Context, secret entity.Secret) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.secrets[secret.ID] = secret
	return nil
}

func (m *mockSecretRepository) Delete(_ context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.secrets, id)
	return nil
}

// --- AuditRepository mock ---

type mockAuditRepository struct {
	logs               []entity.AuditLog
	createErr          error
	listByUserErr      error
	countByUserErr     error
	deleteOlderThanErr error
	countResult        int
}

func newMockAuditRepository() *mockAuditRepository {
	return &mockAuditRepository{}
}

func (m *mockAuditRepository) Create(_ context.Context, log entity.AuditLog) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.logs = append(m.logs, log)
	return nil
}

func (m *mockAuditRepository) ListByUser(_ context.Context, userID, category string, limit, offset int) ([]entity.AuditLog, error) {
	if m.listByUserErr != nil {
		return nil, m.listByUserErr
	}
	var filtered []entity.AuditLog
	for _, l := range m.logs {
		if l.UserID != userID {
			continue
		}
		if category != "" && string(l.Category) != category {
			continue
		}
		filtered = append(filtered, l)
	}
	if offset >= len(filtered) {
		return nil, nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], nil
}

func (m *mockAuditRepository) CountByUser(_ context.Context, userID, category string) (int, error) {
	if m.countByUserErr != nil {
		return 0, m.countByUserErr
	}
	if m.countResult > 0 {
		return m.countResult, nil
	}
	count := 0
	for _, l := range m.logs {
		if l.UserID != userID {
			continue
		}
		if category != "" && string(l.Category) != category {
			continue
		}
		count++
	}
	return count, nil
}

func (m *mockAuditRepository) DeleteOlderThan(_ context.Context, _ string) error {
	return m.deleteOlderThanErr
}

// --- KeyStore mock ---

type mockKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{keys: make(map[string][]byte)}
}

func (m *mockKeyStore) Set(sessionID string, key []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[sessionID] = key
}

func (m *mockKeyStore) Get(sessionID string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[sessionID]
	return k, ok
}

func (m *mockKeyStore) Delete(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, sessionID)
}

func (m *mockKeyStore) DeleteMany(sessionIDs []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range sessionIDs {
		delete(m.keys, id)
	}
}

// --- PasswordHasher mock ---

type mockPasswordHasher struct {
	hashErr    error
	compareErr error
}

func (m *mockPasswordHasher) Hash(password string) (string, error) {
	if m.hashErr != nil {
		return "", m.hashErr
	}
	return "hashed:" + password, nil
}

func (m *mockPasswordHasher) Compare(password, hash string) error {
	if m.compareErr != nil {
		return m.compareErr
	}
	if hash != "hashed:"+password {
		return fmt.Errorf("mismatch")
	}
	return nil
}

// --- KeyDeriver mock ---

type mockKeyDeriver struct{}

func (m *mockKeyDeriver) DeriveKey(_ string, _ []byte) []byte {
	// Exactly 32 bytes for AES-256
	return []byte("01234567890123456789012345678901")
}

// --- MnemonicGenerator mock ---

type mockMnemonicGenerator struct {
	mnemonic string
	err      error
}

func (m *mockMnemonicGenerator) Generate() (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.mnemonic != "" {
		return m.mnemonic, nil
	}
	return "word1 word2 word3 word4 word5 word6", nil
}

// --- IDGenerator mock ---

type mockIDGenerator struct {
	mu      sync.Mutex
	counter int
}

func newMockIDGenerator() *mockIDGenerator {
	return &mockIDGenerator{}
}

func (m *mockIDGenerator) NewID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	return fmt.Sprintf("id-%d", m.counter)
}

// --- MnemonicHasher mock ---

type mockMnemonicHasher struct{}

func (m *mockMnemonicHasher) HashForAuth(mnemonic string) string {
	return "auth:" + mnemonic
}

// --- Encryptor mock ---

type mockEncryptor struct {
	encryptErr error
	decryptErr error
}

func (m *mockEncryptor) Encrypt(plaintext, _ []byte) ([]byte, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	return append([]byte("enc:"), plaintext...), nil
}

func (m *mockEncryptor) Decrypt(ciphertext, _ []byte) ([]byte, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	if len(ciphertext) < 4 || string(ciphertext[:4]) != "enc:" {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return ciphertext[4:], nil
}

// --- Searcher mock ---

type mockSearcher struct {
	scores map[string]float64
}

func newMockSearcher() *mockSearcher {
	return &mockSearcher{scores: make(map[string]float64)}
}

func (m *mockSearcher) Score(query, text string) float64 {
	key := query + "|" + text
	if s, ok := m.scores[key]; ok {
		return s
	}
	return 0.0
}
