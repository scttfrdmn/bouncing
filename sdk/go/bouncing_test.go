package bouncing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── test helpers ─────────────────────────────────────────────────────────────

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func serveJWKS(t *testing.T, pub ed25519.PublicKey, kid string) *httptest.Server {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(pub)
	jwks := fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":%q,"use":"sig","x":%q}]}`, kid, x)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwks))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func signTestToken(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))

	if claims["kid"] == nil {
		claims["kid"] = kid
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	sigInput := header + "." + payload
	sig := ed25519.Sign(priv, []byte(sigInput))
	signature := base64.RawURLEncoding.EncodeToString(sig)

	return sigInput + "." + signature
}

// ── VerifyToken tests ────────────────────────────────────────────────────────

func TestVerifyTokenValid(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	kid := "test-key-1"
	srv := serveJWKS(t, pub, kid)

	client := New(Config{BaseURL: srv.URL})
	// Override JWKS URL to point at test server.
	client.jwks.url = srv.URL

	token := signTestToken(t, priv, kid, map[string]any{
		"sub":         "user-123",
		"email":       "alice@example.com",
		"name":        "Alice",
		"roles":       []string{"admin"},
		"permissions": []string{"*"},
		"exp":         time.Now().Add(15 * time.Minute).Unix(),
		"iat":         time.Now().Unix(),
	})

	session, err := client.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if session.UserID != "user-123" {
		t.Errorf("UserID: got %q", session.UserID)
	}
	if session.Email != "alice@example.com" {
		t.Errorf("Email: got %q", session.Email)
	}
	if len(session.Roles) != 1 || session.Roles[0] != "admin" {
		t.Errorf("Roles: got %v", session.Roles)
	}
}

func TestVerifyTokenExpired(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	kid := "test-key-2"
	srv := serveJWKS(t, pub, kid)

	client := New(Config{BaseURL: srv.URL})
	client.jwks.url = srv.URL

	token := signTestToken(t, priv, kid, map[string]any{
		"sub": "user-123",
		"exp": time.Now().Add(-1 * time.Minute).Unix(),
		"iat": time.Now().Add(-16 * time.Minute).Unix(),
	})

	_, err := client.VerifyToken(context.Background(), token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerifyTokenTampered(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	kid := "test-key-3"
	srv := serveJWKS(t, pub, kid)

	client := New(Config{BaseURL: srv.URL})
	client.jwks.url = srv.URL

	token := signTestToken(t, priv, kid, map[string]any{
		"sub": "user-123",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	// Flip a byte in the signature.
	tampered := token[:len(token)-2] + "xx"

	_, err := client.VerifyToken(context.Background(), tampered)
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestVerifyTokenWrongKey(t *testing.T) {
	t.Parallel()
	pub, _ := generateTestKey(t) // JWKS serves this key
	_, otherPriv := generateTestKey(t) // sign with different key
	kid := "test-key-4"
	srv := serveJWKS(t, pub, kid)

	client := New(Config{BaseURL: srv.URL})
	client.jwks.url = srv.URL

	token := signTestToken(t, otherPriv, kid, map[string]any{
		"sub": "user-123",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	_, err := client.VerifyToken(context.Background(), token)
	if err == nil {
		t.Error("expected error for wrong signing key")
	}
}

func TestVerifyTokenMalformed(t *testing.T) {
	t.Parallel()
	pub, _ := generateTestKey(t)
	srv := serveJWKS(t, pub, "k")

	client := New(Config{BaseURL: srv.URL})
	client.jwks.url = srv.URL

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"one part", "abc"},
		{"two parts", "abc.def"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.VerifyToken(context.Background(), tc.token)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// ── Session helpers ──────────────────────────────────────────────────────────

func TestSessionHasRole(t *testing.T) {
	t.Parallel()
	s := &Session{Roles: []string{"admin", "editor"}}
	if !s.HasRole("admin") {
		t.Error("expected HasRole(admin) = true")
	}
	if s.HasRole("viewer") {
		t.Error("expected HasRole(viewer) = false")
	}
}

func TestSessionHasPermission(t *testing.T) {
	t.Parallel()
	s := &Session{Permissions: []string{"read", "write"}}
	if !s.HasPermission("read") {
		t.Error("expected HasPermission(read) = true")
	}
	if s.HasPermission("delete") {
		t.Error("expected HasPermission(delete) = false")
	}

	// Wildcard
	sw := &Session{Permissions: []string{"*"}}
	if !sw.HasPermission("anything") {
		t.Error("expected wildcard to match anything")
	}
}
