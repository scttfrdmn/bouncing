package oauth

import (
	"io"
	"log/slog"
)

// mockToken satisfies tokenExtraer for testing Apple's id_token parsing.
type mockToken struct {
	idToken string
}

func (m *mockToken) Extra(key string) any {
	if key == "id_token" {
		return m.idToken
	}
	return nil
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
