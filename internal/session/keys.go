// Package session handles Ed25519 key management, JWT issuance/verification,
// refresh token rotation, and the JWKS endpoint.
package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// KeySet holds an Ed25519 keypair and its key ID.
type KeySet struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KID     string
}

// KeyRing holds multiple Ed25519 keypairs. The newest key (by KID) is used for
// signing; all keys are available for verification and served via JWKS.
type KeyRing struct {
	Keys    []*KeySet // sorted newest-first by KID
	Current *KeySet   // alias for Keys[0] — the signing key
}

// LoadAll loads all Ed25519 keypairs from dir. If no keys exist, a new one
// is generated for the current month. Keys are sorted newest-first by KID.
func LoadAll(dir string) (*KeyRing, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("session.LoadAll: mkdir: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("session.LoadAll: readdir: %w", err)
	}

	var keys []*KeySet
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".priv.pem") {
			continue
		}
		kid := strings.TrimSuffix(name, ".priv.pem")
		privPath := filepath.Join(dir, name)
		pubPath := filepath.Join(dir, kid+".pub.pem")

		ks, err := loadKeyPair(kid, privPath, pubPath)
		if err != nil {
			return nil, fmt.Errorf("session.LoadAll: load %s: %w", kid, err)
		}
		keys = append(keys, ks)
	}

	// If no keys exist, generate one for the current month.
	if len(keys) == 0 {
		ks, err := generateKey(dir)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ks)
	}

	// Sort newest-first by KID (lexicographic descending works for YYYY-MM format).
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].KID > keys[j].KID
	})

	return &KeyRing{Keys: keys, Current: keys[0]}, nil
}

// LoadOrGenerate loads or generates a single keypair for backward compatibility.
// It returns a KeyRing with one key.
func LoadOrGenerate(dir string) (*KeyRing, error) {
	return LoadAll(dir)
}

// Rotate generates a new Ed25519 keypair in dir with a unique KID and returns
// the updated KeyRing with the new key as Current.
func Rotate(dir string) (*KeyRing, error) {
	ks, err := generateKey(dir)
	if err != nil {
		return nil, fmt.Errorf("session.Rotate: %w", err)
	}
	_ = ks // the key is now on disk

	return LoadAll(dir)
}

// generateKey creates a new Ed25519 keypair with a timestamped KID.
func generateKey(dir string) (*KeySet, error) {
	kid := "bouncing-" + time.Now().UTC().Format("2006-01-02T150405.000")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("session.generateKey: %w", err)
	}

	privPath := filepath.Join(dir, kid+".priv.pem")
	pubPath := filepath.Join(dir, kid+".pub.pem")

	if err := writePrivKey(privPath, priv); err != nil {
		return nil, err
	}
	if err := writePubKey(pubPath, pub); err != nil {
		return nil, err
	}

	return &KeySet{Private: priv, Public: pub, KID: kid}, nil
}

func loadKeyPair(kid, privPath, _ string) (*KeySet, error) {
	privPEM, err := os.ReadFile(privPath) //nolint:gosec // G304 — path from directory listing, not user input
	if err != nil {
		return nil, fmt.Errorf("session.loadKeyPair: read priv: %w", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("session.loadKeyPair: invalid PEM in %s", privPath)
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("session.loadKeyPair: parse priv: %w", err)
	}
	priv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("session.loadKeyPair: not an Ed25519 private key")
	}

	return &KeySet{
		Private: priv,
		Public:  priv.Public().(ed25519.PublicKey),
		KID:     kid,
	}, nil
}

func writePrivKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("session.writePrivKey: marshal: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return fmt.Errorf("session.writePrivKey: write: %w", err)
	}
	return nil
}

func writePubKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("session.writePubKey: marshal: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0644); err != nil { //nolint:gosec // G306 — public key intentionally world-readable
		return fmt.Errorf("session.writePubKey: write: %w", err)
	}
	return nil
}
