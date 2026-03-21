package service

import (
	"fmt"

	"github.com/00MURALI00/goOauth2/oauth/models"
	"github.com/00MURALI00/goOauth2/oauth/store"
)

type LoginService struct {
	store *store.MemoryStore
}

func NewLoginService(store *store.MemoryStore) *LoginService {
	return &LoginService{
		store: store,
	}
}

func (ls LoginService) Login(username, password string) (models.User, error) {
	user, ok := ls.store.GetUserByUsername(username)
	if !ok {
		return models.User{}, fmt.Errorf("User not found")
	}

	if user.Password != password {
		return models.User{}, fmt.Errorf("User is not authorized")
	}

	return user, nil
}
