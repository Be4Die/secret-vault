package session

import "sync"

type KeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string][]byte),
	}
}

func (s *KeyStore) Set(sessionID string, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[sessionID] = key
}

func (s *KeyStore) Get(sessionID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[sessionID]
	return key, ok
}

func (s *KeyStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, sessionID)
}

func (s *KeyStore) DeleteMany(sessionIDs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range sessionIDs {
		delete(s.keys, id)
	}
}
