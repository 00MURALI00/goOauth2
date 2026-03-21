package service

import (
	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/store"
)

type SubjectService struct {
	store *store.MemoryStore
}

func NewSubjectService(
	store *store.MemoryStore,
) *SubjectService {
	return &SubjectService{
		store: store,
	}
}

func (s *SubjectService) GetSubjectByUserId(userId string) (*models.Subject, error) {
	user, ok := s.store.GetUser(userId)
	if ok {
		return nil, ErrInvalidUser
	}

	subject := &models.Subject{
		Sub:   user.UserId,
		Name:  user.Username,
		Email: user.Email,
	}
	return subject, nil
}
