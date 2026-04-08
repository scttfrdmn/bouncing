package webauthn

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/oklog/ulid/v2"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// webAuthnUser adapts store.User and its credentials to the webauthn.User interface.
type webAuthnUser struct {
	user        *store.User
	credentials []webauthn.Credential
}

func newWebAuthnUser(u *store.User, creds []*store.WebAuthnCredential) *webAuthnUser {
	wCreds := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		wCreds = append(wCreds, webauthn.Credential{
			ID:              []byte(c.ID),
			PublicKey:       c.PublicKey,
			AttestationType: "none",
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	return &webAuthnUser{user: u, credentials: wCreds}
}

func (u *webAuthnUser) WebAuthnID() []byte {
	// Return the 16-byte binary representation of the ULID.
	parsed, err := ulid.Parse(u.user.ID)
	if err != nil {
		// Fallback: return the raw string bytes. This can happen for non-ULID test IDs.
		return []byte(u.user.ID)
	}
	b := parsed.Bytes()
	return b[:]
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.user.Name != "" {
		return u.user.Name
	}
	return u.user.Email
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
