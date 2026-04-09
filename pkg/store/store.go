// Package store exposes the public API surface of the bouncing store layer.
// All types here are type aliases of their internal counterparts, so they are
// completely interchangeable — a struct implementing Store also satisfies the
// internal store.Store interface with no conversion required.
//
// External consumers (e.g. bouncing-managed) should import this package to
// implement custom storage backends such as Turso/libSQL.
package store

import istore "github.com/scttfrdmn/bouncing/internal/store"

// Store is the central storage interface. Every backend implements this.
type Store = istore.Store

// ListOpts controls pagination and filtering for list queries.
type ListOpts = istore.ListOpts

// User represents an authenticated user.
type User = istore.User

// OAuthConnection links a user to a third-party OAuth provider identity.
type OAuthConnection = istore.OAuthConnection

// WebAuthnCredential is a passkey registered by a user.
type WebAuthnCredential = istore.WebAuthnCredential

// Role is a named set of permissions.
type Role = istore.Role

// UserRole records a role assignment, optionally scoped to an org.
type UserRole = istore.UserRole

// Org is a tenant organisation.
type Org = istore.Org

// RefreshToken is an opaque token used to rotate access tokens.
type RefreshToken = istore.RefreshToken

// Webhook is a configured delivery endpoint for lifecycle events.
type Webhook = istore.Webhook

// TOSAcceptance records a user's acceptance of a terms-of-service version.
type TOSAcceptance = istore.TOSAcceptance

// AuditEntry records a single auditable action.
type AuditEntry = istore.AuditEntry

// AuditListOpts controls filtering and pagination for audit queries.
type AuditListOpts = istore.AuditListOpts

// ErrNotFound is returned by store lookups when the record does not exist.
var ErrNotFound = istore.ErrNotFound //nolint:gochecknoglobals

// IsNotFound reports whether err wraps ErrNotFound.
func IsNotFound(err error) bool { return istore.IsNotFound(err) }
