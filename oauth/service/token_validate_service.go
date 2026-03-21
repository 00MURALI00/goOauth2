package service

import (
	"errors"
	"strings"

	"github.com/00MURALI00/goOauth2/oauth/models"
	"github.com/00MURALI00/goOauth2/oauth/store"
	"github.com/00MURALI00/goOauth2/util"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
	ErrInvalidScope = errors.New("invalid scope")
)

type TokenValidateService struct {
	store *store.MemoryStore
}

func NewTokenValidateService(store *store.MemoryStore) *TokenValidateService {
	return &TokenValidateService{
		store: store,
	}
}
func (t *TokenValidateService) ValidateAccessToken (tokenStr string) (*models.AccessToken, error) {
	claims, err := util.ParseAccessToken(tokenStr)

	if err != nil {
		return &models.AccessToken{}, err
	}
	return claims, nil
}

func (t *TokenValidateService) ValidateRefreshToken (tokenStr string) (*models.RefreshToken, error) {
	claims, err := util.ParseRefreshToken(tokenStr)

	if err != nil {
		return &models.RefreshToken{}, err
	}

	return claims, nil
}

func (t *TokenValidateService) GetUserId (tokenStr string) (string, error) {
	claims, err := t.ValidateAccessToken(tokenStr)

	if err != nil {
		return "", err
	}
	return claims.Sub, nil
}

func (t *TokenValidateService) CheckScope (tokenStr string, required []string) error {
	claims, err := t.ValidateAccessToken(tokenStr)
	if err != nil {
		return err
	}

	if strings.Join(claims.Scopes, " ") != strings.Join(required, " ") {
		return ErrInvalidScope
	}

	return nil
}
