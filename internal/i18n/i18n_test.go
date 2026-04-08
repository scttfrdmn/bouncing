package i18n

import (
	"testing"
)

func newTestLocalizer(t *testing.T) *Localizer {
	t.Helper()
	l, err := New("en")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestLocale(t *testing.T) {
	t.Parallel()
	l := newTestLocalizer(t)

	tests := []struct {
		acceptLanguage string
		want           string
	}{
		{"fr", "fr"},
		{"de-AT", "de"},
		{"ja", "ja"},
		{"zh-Hans-CN", "zh-Hans"},
		{"pt-BR", "pt"},
		{"ar", "en"},    // unsupported → fallback
		{"zh-TW", "en"}, // unsupported subtag → fallback
		{"fr;q=0.9,de;q=0.8", "fr"},
		{"de;q=0.8,fr;q=0.9", "fr"}, // q ordering
		{"", "en"},
		{"*", "en"},
	}

	for _, tt := range tests {
		t.Run(tt.acceptLanguage, func(t *testing.T) {
			got := l.Locale(tt.acceptLanguage)
			if got != tt.want {
				t.Errorf("Locale(%q) = %q, want %q", tt.acceptLanguage, got, tt.want)
			}
		})
	}
}

func TestT(t *testing.T) {
	t.Parallel()
	l := newTestLocalizer(t)

	// Basic English lookup.
	got := l.T("en", "signIn.title")
	if got != "Sign in" {
		t.Errorf("T(en, signIn.title) = %q, want %q", got, "Sign in")
	}

	// French lookup.
	got = l.T("fr", "signIn.title")
	if got == "" || got == "signIn.title" {
		t.Errorf("T(fr, signIn.title) = %q, expected non-empty French string", got)
	}

	// Missing key falls back to en.
	got = l.T("fr", "nonexistent.key")
	if got != "nonexistent.key" {
		t.Errorf("missing key: got %q, want raw key", got)
	}

	// Variable substitution.
	got = l.T("en", "signIn.continueWith", map[string]string{"provider": "Google"})
	if !contains(got, "Google") {
		t.Errorf("variable substitution: %q does not contain 'Google'", got)
	}

	// Missing locale falls back to default.
	got = l.T("xx", "signIn.title")
	if got != "Sign in" {
		t.Errorf("unknown locale fallback: got %q, want %q", got, "Sign in")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
