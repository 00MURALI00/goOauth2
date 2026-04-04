package models

import (
	"time"

)

type Session struct {
	ID        string // sid (UUID)
	UserID    string
	ClientID  string
	CreatedAt int64
	ExpiresAt int64
	Revoked   bool
}

func NewSession(id, userId, clientId string, expiresAt int64, revoked bool) *Session {
	return &Session{
		ID:        id,
		UserID:    userId,
		ClientID:  clientId,
		CreatedAt: time.Now().Unix(),
		ExpiresAt: expiresAt,
		Revoked:   revoked,
	}
}
