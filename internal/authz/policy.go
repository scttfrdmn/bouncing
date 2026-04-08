package authz

import (
	"context"
	"errors"
	"strings"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// ErrDomainMismatch is returned when an email's domain is not in the allowed list.
var ErrDomainMismatch = errors.New("domain_mismatch")

// ErrNotInvited is returned in invite-only mode when the email has no pending record.
var ErrNotInvited = errors.New("not_invited")

// Policy enforces access based on the configured mode.
type Policy struct {
	Mode           string   // "open" | "domain-restricted" | "invite-only"
	AllowedDomains []string // lowercased, @ stripped
}

// NewPolicy creates a Policy from config values.
func NewPolicy(mode string, allowedDomains []string) *Policy {
	normalized := make([]string, 0, len(allowedDomains))
	for _, d := range allowedDomains {
		normalized = append(normalized, strings.ToLower(strings.TrimPrefix(d, "@")))
	}
	return &Policy{Mode: mode, AllowedDomains: normalized}
}

// Check validates whether the given email is permitted to authenticate.
// Returns nil on success, ErrDomainMismatch or ErrNotInvited on rejection.
func (p *Policy) Check(ctx context.Context, email string, st store.Store) error {
	switch p.Mode {
	case "open":
		return nil

	case "domain-restricted":
		domain := emailDomain(email)
		for _, allowed := range p.AllowedDomains {
			if strings.EqualFold(domain, allowed) {
				return nil
			}
		}
		return ErrDomainMismatch

	case "invite-only":
		u, err := st.GetUserByEmail(ctx, email)
		if err != nil || u == nil || u.Status != "pending" {
			return ErrNotInvited
		}
		return nil
	}

	return nil
}

// emailDomain extracts the lowercased domain from an email address.
func emailDomain(email string) string {
	idx := strings.LastIndexByte(email, '@')
	if idx < 0 {
		return ""
	}
	return strings.ToLower(email[idx+1:])
}
