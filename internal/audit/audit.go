// Package audit provides a structured audit logger that records actions to the store.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// AuditStore is the subset of store.Store needed by the Logger.
type AuditStore interface {
	CreateAuditEntry(context.Context, *store.AuditEntry) error
}

// Logger records audit entries to the store.
type Logger struct {
	store AuditStore
	log   *slog.Logger
}

// New creates a Logger. If st is nil, all Log calls are no-ops.
func New(st AuditStore, log *slog.Logger) *Logger {
	return &Logger{store: st, log: log}
}

// Log records an audit entry. It extracts IP and request ID from the HTTP
// request (if available in context). metadata is serialized to JSON.
func (l *Logger) Log(ctx context.Context, r *http.Request, actorID, action, targetType, targetID string, metadata map[string]any) {
	if l == nil || l.store == nil {
		return
	}

	var metaJSON string
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err != nil {
			l.log.Warn("audit: marshal metadata", "err", err)
		} else {
			metaJSON = string(b)
		}
	}

	entry := &store.AuditEntry{
		ActorID:    actorID,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   metaJSON,
	}

	if r != nil {
		entry.IPAddress = clientIP(r)
		entry.RequestID = r.Header.Get("X-Request-Id")
	}

	if err := l.store.CreateAuditEntry(ctx, entry); err != nil {
		l.log.Warn("audit: write entry", "action", action, "err", err)
	}
}

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
