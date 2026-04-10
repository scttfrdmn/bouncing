package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestLimiter(rate float64, burst int) *RateLimiter {
	stop := make(chan struct{})
	return NewRateLimiter(rate, burst, true, stop)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimiterAllowsBurst(t *testing.T) {
	t.Parallel()
	rl := newTestLimiter(10, 5)
	handler := rl.Middleware(okHandler())

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "1.2.3.4:12345"
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, w.Code)
		}
	}
}

func TestRateLimiterRejects429AfterBurst(t *testing.T) {
	t.Parallel()
	rl := newTestLimiter(10, 3)
	handler := rl.Middleware(okHandler())

	// Exhaust burst.
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "1.2.3.4:12345"
		handler.ServeHTTP(w, r)
	}

	// Next request should be rejected.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:12345"
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("got %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestRateLimiterRefillsTokens(t *testing.T) {
	t.Parallel()
	// 1000 tokens/sec so a 10ms sleep refills ~10 tokens.
	rl := newTestLimiter(1000, 1)
	handler := rl.Middleware(okHandler())

	// Exhaust the single token.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "5.6.7.8:1111"
	handler.ServeHTTP(w, r)

	// Should be rejected now.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "5.6.7.8:1111"
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}

	// Wait for token to refill.
	time.Sleep(5 * time.Millisecond)

	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "5.6.7.8:1111"
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Errorf("after refill: got %d, want 200", w3.Code)
	}
}

func TestRateLimiterIndependentIPs(t *testing.T) {
	t.Parallel()
	rl := newTestLimiter(10, 1)
	handler := rl.Middleware(okHandler())

	// IP A uses its token.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "10.0.0.1:1111"
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("IP A first: got %d", w1.Code)
	}

	// IP A is now exhausted.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.1:1111"
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A second: got %d, want 429", w2.Code)
	}

	// IP B should still work.
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "10.0.0.2:2222"
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Errorf("IP B: got %d, want 200", w3.Code)
	}
}

func TestRateLimiterXForwardedFor(t *testing.T) {
	t.Parallel()
	rl := newTestLimiter(10, 1)
	handler := rl.Middleware(okHandler())

	// Use X-Forwarded-For with multiple entries.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("first XFF request: got %d", w.Code)
	}

	// Exhaust 203.0.113.50's bucket.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "127.0.0.1:9999"
	r2.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	handler.ServeHTTP(w2, r2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("XFF second request: got %d, want 429", w2.Code)
	}
}

func TestClientIPFallback(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:5555"
	if got := clientIPWith(r, true); got != "192.168.1.1" {
		t.Errorf("clientIP: got %q, want 192.168.1.1", got)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "badaddr"
	if got := clientIPWith(r2, true); got != "badaddr" {
		t.Errorf("clientIP fallback: got %q, want badaddr", got)
	}
}
