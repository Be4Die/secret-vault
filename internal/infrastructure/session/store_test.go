package session_test

import (
	"bytes"
	"sync"
	"testing"

	"secret-vault/internal/infrastructure/session"
)

func TestKeyStore_SetAndGet(t *testing.T) {
	s := session.NewKeyStore()

	key := []byte("encryption-key")
	s.Set("session-1", key)

	got, ok := s.Get("session-1")
	if !ok {
		t.Fatal("expected key to exist")
	}
	if !bytes.Equal(got, key) {
		t.Errorf("got %q, want %q", got, key)
	}
}

func TestKeyStore_GetMissing(t *testing.T) {
	s := session.NewKeyStore()

	_, ok := s.Get("nonexistent")
	if ok {
		t.Error("expected key to not exist")
	}
}

func TestKeyStore_Delete(t *testing.T) {
	s := session.NewKeyStore()

	s.Set("session-1", []byte("key"))
	s.Delete("session-1")

	_, ok := s.Get("session-1")
	if ok {
		t.Error("expected key to be deleted")
	}
}

func TestKeyStore_DeleteNonexistent(t *testing.T) {
	s := session.NewKeyStore()

	// Should not panic
	s.Delete("nonexistent")
}

func TestKeyStore_DeleteMany(t *testing.T) {
	s := session.NewKeyStore()

	s.Set("s1", []byte("k1"))
	s.Set("s2", []byte("k2"))
	s.Set("s3", []byte("k3"))

	s.DeleteMany([]string{"s1", "s3"})

	if _, ok := s.Get("s1"); ok {
		t.Error("s1 should be deleted")
	}
	if _, ok := s.Get("s2"); !ok {
		t.Error("s2 should remain")
	}
	if _, ok := s.Get("s3"); ok {
		t.Error("s3 should be deleted")
	}
}

func TestKeyStore_DeleteManyEmpty(t *testing.T) {
	s := session.NewKeyStore()
	s.Set("s1", []byte("k1"))

	// Should not panic
	s.DeleteMany(nil)
	s.DeleteMany([]string{})

	if _, ok := s.Get("s1"); !ok {
		t.Error("s1 should remain after empty DeleteMany")
	}
}

func TestKeyStore_Overwrite(t *testing.T) {
	s := session.NewKeyStore()

	s.Set("session-1", []byte("old-key"))
	s.Set("session-1", []byte("new-key"))

	got, ok := s.Get("session-1")
	if !ok {
		t.Fatal("expected key to exist")
	}
	if !bytes.Equal(got, []byte("new-key")) {
		t.Errorf("expected overwritten value, got %q", got)
	}
}

func TestKeyStore_Concurrent(t *testing.T) {
	s := session.NewKeyStore()

	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent writes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := []byte("key-data")
			sid := "session"
			s.Set(sid, key)
			s.Get(sid)
			s.Delete(sid)
		}(i)
	}

	wg.Wait()
}

func TestKeyStore_IsolatedSessions(t *testing.T) {
	s := session.NewKeyStore()

	s.Set("s1", []byte("key-1"))
	s.Set("s2", []byte("key-2"))

	k1, _ := s.Get("s1")
	k2, _ := s.Get("s2")

	if bytes.Equal(k1, k2) {
		t.Error("different sessions should have different keys")
	}

	s.Delete("s1")

	if _, ok := s.Get("s1"); ok {
		t.Error("s1 should be deleted")
	}
	if _, ok := s.Get("s2"); !ok {
		t.Error("s2 should still exist")
	}
}
