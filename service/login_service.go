package service

import (
	"errors"
	"fmt"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/store"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound     = errors.New("User not found")
	ErrUserUnAuthorized = errors.New("User is not authorized")
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
		return models.User{}, ErrUserNotFound
	}
	fmt.Printf("DEBUG: Comparing incoming '%s' against stored hash '%s'\n", password, user.Password)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return models.User{}, ErrUserUnAuthorized
	}

	return user, nil
}
