package server

import (
	"context"

	"github.com/scttfrdmn/bouncing/internal/session"
)

type contextKey int

const (
	claimsKey    contextKey = iota
	requestIDKey contextKey = iota
)

// ClaimsFromContext returns the JWT claims stored by RequireAuth middleware.
func ClaimsFromContext(ctx context.Context) *session.Claims {
	v, _ := ctx.Value(claimsKey).(*session.Claims)
	return v
}

// RequestIDFromContext returns the request ID stored by the RequestID middleware.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}
