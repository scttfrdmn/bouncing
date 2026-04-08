package webauthn

import (
	"github.com/scttfrdmn/bouncing/internal/store"
)

func newTestUser(id string) *store.User {
	return &store.User{
		ID:     id,
		Email:  "test+" + id + "@example.com",
		Name:   "Test User",
		Status: "active",
	}
}
