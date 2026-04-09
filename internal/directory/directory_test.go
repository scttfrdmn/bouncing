package directory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── mock Provider ─────────────────────────────────────────────────────────────

type mockProvider struct {
	users []*DirectoryUser
	err   error
}

func (m *mockProvider) ListUsers(_ context.Context) ([]*DirectoryUser, error) {
	return m.users, m.err
}

// ── mock SyncStore ────────────────────────────────────────────────────────────

type mockStore struct {
	users   map[string]*store.User // keyed by email
	created []*store.User
	updated []*store.User
}

func newMockStore(users ...*store.User) *mockStore {
	m := &mockStore{users: make(map[string]*store.User)}
	for _, u := range users {
		m.users[u.Email] = u
	}
	return m
}

func (m *mockStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	u, ok := m.users[email]
	if !ok {
		return nil, fmt.Errorf("get: %w", store.ErrNotFound) //nolint:goerr113
	}
	return u, nil
}

func (m *mockStore) CreateUser(_ context.Context, u *store.User) error {
	if u.ID == "" {
		u.ID = "generated-" + u.Email
	}
	m.users[u.Email] = u
	m.created = append(m.created, u)
	return nil
}

func (m *mockStore) UpdateUser(_ context.Context, u *store.User) error {
	m.users[u.Email] = u
	m.updated = append(m.updated, u)
	return nil
}

// ── mock SyncHooks ────────────────────────────────────────────────────────────

type mockHooks struct {
	events []string
}

func (m *mockHooks) Dispatch(_ context.Context, event string, _ any) {
	m.events = append(m.events, event)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newSyncer(p Provider, st SyncStore, h SyncHooks, mode string) *Syncer {
	return New(p, st, h, mode, noopLogger())
}

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestSyncCreatesNewUser(t *testing.T) {
	t.Parallel()
	p := &mockProvider{users: []*DirectoryUser{
		{Email: "alice@acme.com", Name: "Alice", Suspended: false},
	}}
	st := newMockStore()
	h := &mockHooks{}
	syncer := newSyncer(p, st, h, "open")

	result, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Created != 1 {
		t.Errorf("Created: got %d, want 1", result.Created)
	}
	if result.Updated != 0 {
		t.Errorf("Updated: got %d, want 0", result.Updated)
	}
	if len(h.events) != 1 || h.events[0] != "user.created" {
		t.Errorf("events: got %v, want [user.created]", h.events)
	}
	if len(st.created) != 1 || st.created[0].Email != "alice@acme.com" {
		t.Errorf("store.created: %+v", st.created)
	}
}

func TestSyncSkipsInviteOnlyMode(t *testing.T) {
	t.Parallel()
	p := &mockProvider{users: []*DirectoryUser{
		{Email: "bob@acme.com", Name: "Bob"},
	}}
	st := newMockStore()
	syncer := newSyncer(p, st, nil, "invite-only")

	result, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Created != 0 {
		t.Errorf("Created: got %d, want 0", result.Created)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped: got %d, want 1", result.Skipped)
	}
	if len(st.created) != 0 {
		t.Errorf("expected no users created")
	}
}

func TestSyncSuspendsActiveUser(t *testing.T) {
	t.Parallel()
	existing := &store.User{ID: "u1", Email: "carol@acme.com", Status: "active"}
	p := &mockProvider{users: []*DirectoryUser{
		{Email: "carol@acme.com", Name: "Carol", Suspended: true},
	}}
	st := newMockStore(existing)
	syncer := newSyncer(p, st, nil, "open")

	result, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Updated != 1 {
		t.Errorf("Updated: got %d, want 1", result.Updated)
	}
	if st.users["carol@acme.com"].Status != "suspended" {
		t.Errorf("status: got %q, want suspended", st.users["carol@acme.com"].Status)
	}
}

func TestSyncSkipsAlreadySuspended(t *testing.T) {
	t.Parallel()
	existing := &store.User{ID: "u2", Email: "dave@acme.com", Status: "suspended"}
	p := &mockProvider{users: []*DirectoryUser{
		{Email: "dave@acme.com", Suspended: true},
	}}
	st := newMockStore(existing)
	syncer := newSyncer(p, st, nil, "open")

	result, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped: got %d, want 1", result.Skipped)
	}
	if len(st.updated) != 0 {
		t.Errorf("expected no updates")
	}
}

func TestSyncProviderError(t *testing.T) {
	t.Parallel()
	p := &mockProvider{err: errors.New("google api unavailable")}
	st := newMockStore()
	syncer := newSyncer(p, st, nil, "open")

	_, err := syncer.Run(context.Background())
	if err == nil {
		t.Error("expected error when provider fails")
	}
}

func TestSyncMixedResults(t *testing.T) {
	t.Parallel()
	existing := &store.User{ID: "u1", Email: "active@acme.com", Status: "active"}
	p := &mockProvider{users: []*DirectoryUser{
		{Email: "new@acme.com", Name: "New User"},                     // create
		{Email: "active@acme.com", Name: "Active", Suspended: true},   // suspend
		{Email: "unknown@acme.com", Name: "Unknown", Suspended: false}, // create
	}}
	st := newMockStore(existing)
	h := &mockHooks{}
	syncer := newSyncer(p, st, h, "open")

	result, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Created != 2 {
		t.Errorf("Created: got %d, want 2", result.Created)
	}
	if result.Updated != 1 {
		t.Errorf("Updated: got %d, want 1", result.Updated)
	}
	if st.users["active@acme.com"].Status != "suspended" {
		t.Errorf("status: got %q, want suspended", st.users["active@acme.com"].Status)
	}
}

func TestSyncNilHooks(t *testing.T) {
	t.Parallel()
	p := &mockProvider{users: []*DirectoryUser{
		{Email: "nohooks@acme.com"},
	}}
	st := newMockStore()
	syncer := newSyncer(p, st, nil, "open")

	result, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Created != 1 {
		t.Errorf("Created: got %d, want 1", result.Created)
	}
}

func TestNewGoogleProviderBadFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, err := NewGoogleProvider(ctx, &config.DirectoryConfig{
		Domain:         "acme.com",
		ServiceAccount: "/nonexistent/path/sa.json",
		AdminEmail:     "admin@acme.com",
	})
	if err == nil {
		t.Error("expected error for nonexistent service account file")
	}
}

func TestNewGoogleProviderValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name string
		cfg  *config.DirectoryConfig
	}{
		{"missing domain", &config.DirectoryConfig{ServiceAccount: "/x", AdminEmail: "a@b.com"}},
		{"missing service_account", &config.DirectoryConfig{Domain: "acme.com", AdminEmail: "a@b.com"}},
		{"missing admin_email", &config.DirectoryConfig{Domain: "acme.com", ServiceAccount: "/x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewGoogleProvider(ctx, tc.cfg)
			if err == nil {
				t.Error("expected validation error")
			}
		})
	}
}
