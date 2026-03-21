package util

import (
	"time"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("jet_secret")
var Expiry = 5 * time.Minute

func SignAccessToken(userId, clientId, epxiry string, scope []string) (*models.AccessToken, string, error) {
	claims := &models.AccessToken{
		Sub:      userId,
		ClientId: clientId,
		Scopes:   scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(Expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtSecret)

	return claims, tokenStr, err
}

func SignRefreshToken(userId, clientId string, scope []string, expiry time.Duration) (*models.RefreshToken, string, error) {
	claims := &models.RefreshToken{
		Sub:      userId,
		ClientId: clientId,
		Scope: scope,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtSecret)

	return claims, tokenStr, err
}

func ParseAccessToken(tokenStr string) (*models.AccessToken, error) {
	claims := &models.AccessToken{}

	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			return jwtSecret, nil
		})

	if err != nil {
		return &models.AccessToken{}, err
	}

	if !token.Valid {
		return &models.AccessToken{}, jwt.ErrTokenInvalidClaims
	}

	return claims, nil
}

func ParseRefreshToken(tokenStr string) (*models.RefreshToken, error) {
	claims := &models.RefreshToken{}

	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(t *jwt.Token) (any, error) {
			return jwtSecret, nil
		},
	)

	if err != nil {
		return &models.RefreshToken{}, err
	}

	if !token.Valid {
		return &models.RefreshToken{}, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}
