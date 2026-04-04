package service

import (
	"github.com/00MURALI00/goOauth2/store"
	"github.com/00MURALI00/goOauth2/util"
)

type LogoutService struct {
	store *store.MemoryStore
}

func NewLogoutService(store *store.MemoryStore) *LogoutService {
	return &LogoutService{
		store: store,
	}
}

func (ls *LogoutService) Logout(token string) error {
	accessToken, err := util.ParseAccessToken(token)
	if err != nil {
		return err
	}

	session, ok := ls.store.GetSessionById(accessToken.SId)
	if !ok {
		return ErrInvalidSessionID
	}

	session.Revoked = true
	return nil
}
