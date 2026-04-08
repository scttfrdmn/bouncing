package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// Dispatcher sends webhook events asynchronously with retry.
type Dispatcher struct {
	webhooks []config.WebhookConfig
	store    store.Store // optional; provides dynamically-added webhooks
	client   *http.Client
	log      *slog.Logger
}

// NewDispatcher creates a Dispatcher from the given webhook configs.
func NewDispatcher(webhooks []config.WebhookConfig, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		webhooks: webhooks,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
	}
}

// WithStore attaches a store so that webhooks persisted via the management API
// are also dispatched alongside config-file webhooks.
func (d *Dispatcher) WithStore(s store.Store) {
	d.store = s
}

// Dispatch fires event asynchronously to all matching webhooks.
// It unions config-file webhooks with any persisted in the store.
func (d *Dispatcher) Dispatch(ctx context.Context, event string, payload any) {
	// Config-file webhooks.
	for _, wh := range d.webhooks {
		if !eventMatches(wh.Events, event) {
			continue
		}
		wh := wh
		go d.send(context.Background(), wh, event, payload)
	}
	// Store-persisted webhooks (registered via management API).
	if d.store != nil {
		storeWhs, err := d.store.ListWebhooks(context.Background())
		if err != nil {
			d.log.Warn("hooks: list store webhooks", "err", err)
			return
		}
		for _, sw := range storeWhs {
			if !eventMatches(sw.Events, event) {
				continue
			}
			sw := sw
			go d.send(context.Background(), config.WebhookConfig{
				URL:    sw.URL,
				Events: sw.Events,
				Secret: sw.Secret,
			}, event, payload)
		}
	}
}

func (d *Dispatcher) send(ctx context.Context, wh config.WebhookConfig, event string, payload any) {
	body, err := json.Marshal(map[string]any{
		"event":   event,
		"payload": payload,
	})
	if err != nil {
		d.log.Error("hooks: marshal payload", "event", event, "err", err)
		return
	}

	delays := []time.Duration{1 * time.Second, 5 * time.Second, 30 * time.Second}
	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delays[attempt-1]):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", wh.URL, bytes.NewReader(body))
		if err != nil {
			d.log.Error("hooks: build request", "url", wh.URL, "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Bouncing-Event", event)
		if wh.Secret != "" {
			req.Header.Set("X-Hub-Signature-256", Sign(body, wh.Secret))
		}

		resp, err := d.client.Do(req)
		if err != nil {
			d.log.Warn("hooks: send failed", "url", wh.URL, "attempt", attempt+1, "err", err)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		d.log.Warn("hooks: non-2xx response", "url", wh.URL, "status", resp.StatusCode, "attempt", attempt+1)
	}
	d.log.Error("hooks: all retries exhausted", "url", wh.URL, "event", event)
}

func eventMatches(patterns []string, event string) bool {
	for _, p := range patterns {
		if p == "*" || p == event {
			return true
		}
	}
	return false
}
