package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a per-IP token-bucket rate limiter.
// Each IP gets a bucket of burst tokens that refills at rate tokens/second.
type RateLimiter struct {
	rate    float64  // tokens per second
	burst   int      // max bucket size
	buckets sync.Map // string → *bucket
	stop    chan struct{}
}

type bucket struct {
	mu       sync.Mutex
	tokens   float64
	lastTime time.Time
}

// NewRateLimiter creates a RateLimiter and starts a background cleanup goroutine.
// The cleanup goroutine exits when stop is closed.
func NewRateLimiter(rate float64, burst int, stop chan struct{}) *RateLimiter {
	rl := &RateLimiter{
		rate:  rate,
		burst: burst,
		stop:  stop,
	}
	go rl.cleanup()
	return rl
}

// Middleware returns an http.Handler that enforces the rate limit.
// If rate is 0, the middleware is a no-op (rate limiting disabled).
// Requests exceeding the limit receive 429 with a Retry-After header.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	if rl.rate <= 0 || rl.burst <= 0 {
		return next // disabled
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			retryAfter := math.Ceil(1.0 / rl.rate)
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter)))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow checks whether the given key has a token available.
func (rl *RateLimiter) allow(key string) bool {
	now := time.Now()
	v, _ := rl.buckets.LoadOrStore(key, &bucket{
		tokens:   float64(rl.burst),
		lastTime: now,
	})
	b := v.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanup removes stale buckets every 60 seconds.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stop:
			return
		case <-ticker.C:
			staleThreshold := time.Now().Add(-2 * time.Duration(float64(rl.burst)/rl.rate) * time.Second)
			rl.buckets.Range(func(key, value any) bool {
				b := value.(*bucket)
				b.mu.Lock()
				lastTime := b.lastTime
				b.mu.Unlock()
				if lastTime.Before(staleThreshold) {
					rl.buckets.Delete(key)
				}
				return true
			})
		}
	}
}

// clientIP extracts the client IP address from the request.
// It checks X-Forwarded-For first (first entry), then falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
