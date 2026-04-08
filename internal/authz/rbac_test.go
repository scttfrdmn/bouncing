package authz

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/store"
)

var engine = &Engine{}

// ── HasPermission ─────────────────────────────────────────────────────────────

func TestHasPermission(t *testing.T) {
	t.Parallel()
	tests := []struct {
		perms    []string
		required string
		want     bool
	}{
		{[]string{"content:read", "content:write"}, "content:read", true},
		{[]string{"content:read"}, "content:write", false},
		{[]string{"*"}, "anything", true},
		{[]string{"*"}, "admin:delete", true},
		{[]string{}, "content:read", false},
	}
	for _, tt := range tests {
		got := engine.HasPermission(tt.perms, tt.required)
		if got != tt.want {
			t.Errorf("HasPermission(%v, %q) = %v, want %v", tt.perms, tt.required, got, tt.want)
		}
	}
}

// ── HasRole ───────────────────────────────────────────────────────────────────

func TestHasRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		roles    []string
		required string
		want     bool
	}{
		{[]string{"admin", "editor"}, "admin", true},
		{[]string{"editor"}, "admin", false},
		{[]string{}, "admin", false},
	}
	for _, tt := range tests {
		got := engine.HasRole(tt.roles, tt.required)
		if got != tt.want {
			t.Errorf("HasRole(%v, %q) = %v, want %v", tt.roles, tt.required, got, tt.want)
		}
	}
}

// ── MergePermissions ──────────────────────────────────────────────────────────

func TestMergePermissions(t *testing.T) {
	t.Parallel()

	roles := []*store.Role{
		{Name: "editor", Permissions: []string{"content:read", "content:write"}},
		{Name: "reviewer", Permissions: []string{"content:read", "content:review"}},
	}
	got := engine.MergePermissions(roles)

	// Must be sorted and deduplicated.
	want := []string{"content:read", "content:review", "content:write"}
	if len(got) != len(want) {
		t.Fatalf("MergePermissions: got %v, want %v", got, want)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("MergePermissions[%d]: got %q, want %q", i, got[i], p)
		}
	}
}

func TestMergePermissionsWildcard(t *testing.T) {
	t.Parallel()
	roles := []*store.Role{
		{Name: "admin", Permissions: []string{"*"}},
		{Name: "editor", Permissions: []string{"content:read"}},
	}
	got := engine.MergePermissions(roles)
	// Both should be present, sorted.
	if len(got) != 2 {
		t.Errorf("expected 2 permissions, got %v", got)
	}
	if got[0] != "*" {
		t.Errorf("expected * first (sorts before letters), got %v", got)
	}
}

// ── Policy ────────────────────────────────────────────────────────────────────

type mockStore struct {
	store.Store
	user *store.User
	err  error
}

func (m *mockStore) GetUserByEmail(_ context.Context, _ string) (*store.User, error) {
	return m.user, m.err
}

func TestPolicyOpen(t *testing.T) {
	t.Parallel()
	p := NewPolicy("open", nil)
	if err := p.Check(context.Background(), "anyone@gmail.com", &mockStore{}); err != nil {
		t.Errorf("open mode: unexpected error %v", err)
	}
}

func TestPolicyDomainRestricted(t *testing.T) {
	t.Parallel()
	p := NewPolicy("domain-restricted", []string{"@enso.co", "@playgroundlogic.co"})

	tests := []struct {
		email   string
		wantErr error
	}{
		{"scott@enso.co", nil},
		{"SCOTT@ENSO.CO", nil}, // case-insensitive
		{"maya@playgroundlogic.co", nil},
		{"random@gmail.com", ErrDomainMismatch},
		{"scott@sub.enso.co", ErrDomainMismatch}, // no subdomain
	}
	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			err := p.Check(context.Background(), tt.email, &mockStore{})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Check(%q): got %v, want %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestPolicyInviteOnly(t *testing.T) {
	t.Parallel()
	p := NewPolicy("invite-only", nil)

	// Pending user → allowed.
	err := p.Check(context.Background(), "scott@enso.co", &mockStore{
		user: &store.User{Email: "scott@enso.co", Status: "pending"},
	})
	if err != nil {
		t.Errorf("pending user: unexpected error %v", err)
	}

	// Active user (already activated) → still allowed.
	err = p.Check(context.Background(), "scott@enso.co", &mockStore{
		user: &store.User{Email: "scott@enso.co", Status: "active"},
	})
	if !errors.Is(err, ErrNotInvited) {
		t.Errorf("active user in invite-only: expected ErrNotInvited, got %v", err)
	}

	// Not found → not invited.
	err = p.Check(context.Background(), "unknown@enso.co", &mockStore{
		err: sql.ErrNoRows,
	})
	if !errors.Is(err, ErrNotInvited) {
		t.Errorf("unknown user: expected ErrNotInvited, got %v", err)
	}
}
