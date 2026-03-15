package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"secret-vault/internal/usecase"
)

const pendingTTL = 10 * time.Minute

type pendingEntry struct {
	data      *usecase.PendingRegistration
	expiresAt time.Time
}

type PendingStore struct {
	mu      sync.Mutex
	entries map[string]pendingEntry
}

func NewPendingStore() *PendingStore {
	store := &PendingStore{
		entries: make(map[string]pendingEntry),
	}
	go store.cleanup()
	return store
}

func (s *PendingStore) Store(pending *usecase.PendingRegistration) string {
	token := generateToken()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[token] = pendingEntry{
		data:      pending,
		expiresAt: time.Now().Add(pendingTTL),
	}

	slog.Debug("pending store: saved", "token_prefix", token[:8], "total_entries", len(s.entries))

	return token
}

func (s *PendingStore) Get(token string) *usecase.PendingRegistration {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[token]
	if !ok {
		slog.Debug("pending store: token not found", "token_prefix", token[:min(8, len(token))], "total_entries", len(s.entries))
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		slog.Debug("pending store: token expired", "token_prefix", token[:8])
		delete(s.entries, token)
		return nil
	}

	return entry.data
}

func (s *PendingStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, token)
}

func (s *PendingStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, entry := range s.entries {
			if now.After(entry.expiresAt) {
				delete(s.entries, token)
			}
		}
		s.mu.Unlock()
	}
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
