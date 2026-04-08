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
	"time"
)

// KeySet holds an Ed25519 keypair and its key ID.
type KeySet struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KID     string
}

// LoadOrGenerate loads the current month's Ed25519 keypair from dir, generating
// and persisting it if it does not yet exist.
// KID format: "bouncing-YYYY-MM"
func LoadOrGenerate(dir string) (*KeySet, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("session.LoadOrGenerate: mkdir: %w", err)
	}

	kid := "bouncing-" + time.Now().UTC().Format("2006-01")
	privPath := filepath.Join(dir, kid+".priv.pem")
	pubPath := filepath.Join(dir, kid+".pub.pem")

	// Try to load existing keys.
	if _, err := os.Stat(privPath); err == nil {
		return loadKeyPair(kid, privPath, pubPath)
	}

	// Generate new Ed25519 keypair.
	// Note: ed25519.GenerateKey returns (PublicKey, PrivateKey, error).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("session.LoadOrGenerate: generate: %w", err)
	}

	if err := writePrivKey(privPath, priv); err != nil {
		return nil, err
	}
	if err := writePubKey(pubPath, pub); err != nil {
		return nil, err
	}

	return &KeySet{Private: priv, Public: pub, KID: kid}, nil
}

func loadKeyPair(kid, privPath, pubPath string) (*KeySet, error) {
	privPEM, err := os.ReadFile(privPath)
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
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		return fmt.Errorf("session.writePubKey: write: %w", err)
	}
	return nil
}
