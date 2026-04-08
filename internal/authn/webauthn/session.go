package webauthn

import (
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type sessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

// SessionStore holds short-lived WebAuthn ceremony session data in memory.
// TTL is 5 minutes. A background goroutine cleans up expired entries every minute.
type SessionStore struct {
	mu      sync.Mutex
	entries map[string]*sessionEntry
}

// NewSessionStore creates a SessionStore and starts the cleanup goroutine.
// The goroutine exits when the stop channel is closed.
func NewSessionStore(stop <-chan struct{}) *SessionStore {
	s := &SessionStore{
		entries: make(map[string]*sessionEntry),
	}
	go s.cleanup(stop)
	return s
}

// Save stores session data keyed by userID. Any existing entry is replaced.
func (s *SessionStore) Save(userID string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[userID] = &sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
}

// Load retrieves and removes session data for userID.
// Returns nil if not found or expired.
func (s *SessionStore) Load(userID string) *webauthn.SessionData {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[userID]
	if !ok {
		return nil
	}
	delete(s.entries, userID)
	if time.Now().After(e.expiresAt) {
		return nil
	}
	return e.data
}

func (s *SessionStore) cleanup(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, e := range s.entries {
				if now.After(e.expiresAt) {
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
