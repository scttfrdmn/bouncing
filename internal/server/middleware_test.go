package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
		"Permissions-Policy":    "camera=(), microphone=(), geolocation=()",
	}
	for header, want := range expected {
		got := w.Header().Get(header)
		if got != want {
			t.Errorf("%s: got %q, want %q", header, got, want)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP: got %q", csp)
	}
}

func TestSecurityHeadersHSTS(t *testing.T) {
	t.Parallel()
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without TLS — no HSTS.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS should not be set without TLS")
	}

	// With X-Forwarded-Proto: https — HSTS set.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("X-Forwarded-Proto", "https")
	handler.ServeHTTP(w2, r2)
	hsts := w2.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=63072000") {
		t.Errorf("HSTS: got %q", hsts)
	}
}

func TestMaxBodySize(t *testing.T) {
	t.Parallel()
	handler := MaxBodySize(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 100)
		_, err := r.Body.Read(buf)
		if err != nil && err.Error() == "http: request body too large" {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Small body — OK.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader("short"))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("small body: got %d, want 200", w.Code)
	}

	// Large body — limited.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 100)))
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: got %d, want 413", w2.Code)
	}
}
