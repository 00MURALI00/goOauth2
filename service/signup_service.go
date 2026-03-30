package service

import (
	"errors"
	"fmt"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/store"
	"github.com/00MURALI00/goOauth2/util"
)

var (
	ErrUserExist              = errors.New("User already exist")
	ErrUserIdGenerationFailed = errors.New("Failed To generate user Id")
	ErrPasswordHashing        = errors.New("Failed Hash Password")
)

type SignupService struct {
	store *store.MemoryStore
}

func NewSignupService(store *store.MemoryStore) *SignupService {
	return &SignupService{
		store: store,
	}
}

func (s *SignupService) SignupUser(user *models.User) error {
	_, ok := s.store.GetUserByUsername(user.Username)
	if ok {
		return ErrUserExist
	}

	user.UserId = util.GenerateId()
	fmt.Printf("UserID: %s \n", user.UserId)
	if user.UserId == "" {
		return ErrUserIdGenerationFailed
	}
	user.Password, user.Salt = util.SaltAndHashPassword(user.Password)
	fmt.Printf("User Password: %s \n", user.Password)
	if user.Password == "" || user.Salt == "" {
		return ErrPasswordHashing
	}

	s.store.SaveUserById(*user)

	return nil
}
