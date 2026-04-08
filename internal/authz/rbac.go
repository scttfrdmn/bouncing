// Package authz implements role-based access control and access policy enforcement.
package authz

import (
	"sort"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// Engine evaluates permissions and merges role sets.
type Engine struct{}

// HasPermission returns true if the required permission is granted.
// A wildcard entry "*" grants all permissions.
func (e *Engine) HasPermission(permissions []string, required string) bool {
	for _, p := range permissions {
		if p == "*" || p == required {
			return true
		}
	}
	return false
}

// HasRole returns true if required is present in the roles slice.
func (e *Engine) HasRole(roles []string, required string) bool {
	for _, r := range roles {
		if r == required {
			return true
		}
	}
	return false
}

// MergePermissions unions all permissions from the given roles, deduplicates,
// and returns them sorted. The result is deterministic — safe to embed in JWTs.
func (e *Engine) MergePermissions(roles []*store.Role) []string {
	seen := make(map[string]struct{})
	for _, r := range roles {
		for _, p := range r.Permissions {
			seen[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
