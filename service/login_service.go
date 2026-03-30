package service

import (
	"fmt"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/store"
	"golang.org/x/crypto/bcrypt"
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

	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password)); err != nil {
		return models.User{}, fmt.Errorf("User is not authorized")
	}

	return user, nil
}
