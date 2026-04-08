// Package directory provides user provisioning from external directory services
// (Google Workspace, etc.) into the bouncing user store.
package directory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/scttfrdmn/bouncing/internal/hooks"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// Provider fetches users from a directory service.
type Provider interface {
	ListUsers(ctx context.Context) ([]*DirectoryUser, error)
}

// DirectoryUser is a user fetched from a directory service.
type DirectoryUser struct {
	Email     string
	Name      string
	AvatarURL string
	Suspended bool
}

// SyncStore is the subset of store.Store needed by the Syncer.
type SyncStore interface {
	GetUserByEmail(context.Context, string) (*store.User, error)
	CreateUser(context.Context, *store.User) error
	UpdateUser(context.Context, *store.User) error
}

// SyncHooks dispatches user lifecycle events.
type SyncHooks interface {
	Dispatch(ctx context.Context, event string, payload any)
}

// SyncResult summarises a single sync run.
type SyncResult struct {
	Created int
	Updated int
	Skipped int
}

// Syncer runs directory sync against a SyncStore.
type Syncer struct {
	provider   Provider
	store      SyncStore
	hooks      SyncHooks // optional
	accessMode string    // "open" | "domain-restricted" | "invite-only"
	log        *slog.Logger
}

// New constructs a Syncer. hooks may be nil.
func New(p Provider, st SyncStore, h SyncHooks, accessMode string, log *slog.Logger) *Syncer {
	return &Syncer{
		provider:   p,
		store:      st,
		hooks:      h,
		accessMode: accessMode,
		log:        log,
	}
}

// Run fetches directory users and syncs them into the store.
//
// For each directory user:
//   - If the user does not exist and access mode is not "invite-only", a new
//     active user is created and a user.created event is fired.
//   - If the user exists and is suspended in the directory, their status is
//     updated to "suspended" in the store.
//   - Otherwise the user is skipped.
func (s *Syncer) Run(ctx context.Context) (*SyncResult, error) {
	users, err := s.provider.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("directory: list users: %w", err)
	}

	result := &SyncResult{}

	for _, du := range users {
		existing, err := s.store.GetUserByEmail(ctx, du.Email)
		switch {
		case err == nil:
			// User exists — update status if suspended in directory.
			if du.Suspended && existing.Status == "active" {
				existing.Status = "suspended"
				if uerr := s.store.UpdateUser(ctx, existing); uerr != nil {
					s.log.Warn("directory: update user", "email", du.Email, "err", uerr)
					continue
				}
				result.Updated++
			} else {
				result.Skipped++
			}

		case errors.Is(err, store.ErrNotFound):
			// New user — create unless invite-only.
			if s.accessMode == "invite-only" {
				result.Skipped++
				continue
			}
			u := &store.User{
				Email:      du.Email,
				Name:       du.Name,
				AvatarURL:  du.AvatarURL,
				Status:     "active",
				AuthMethod: "directory:google",
			}
			if cerr := s.store.CreateUser(ctx, u); cerr != nil {
				s.log.Warn("directory: create user", "email", du.Email, "err", cerr)
				continue
			}
			if s.hooks != nil {
				s.hooks.Dispatch(ctx, hooks.EventUserCreated, map[string]any{
					"user_id": u.ID,
					"email":   u.Email,
					"method":  "directory:google",
				})
			}
			result.Created++

		default:
			s.log.Warn("directory: get user", "email", du.Email, "err", err)
		}
	}

	return result, nil
}
