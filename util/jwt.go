package util

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/golang-jwt/jwt/v5"
)

var ExpiryAccessAndIDToken = 5 * time.Minute
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

func init() {
	LoadPrivateKey()
	LoadPublicKey()
}

func LoadPublicKey() error {
	keyData, err := os.ReadFile("public.pem")
	if err != nil {
		return err
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(keyData)
	return err
}

func LoadPrivateKey() error {
	keyData, err := os.ReadFile("private.pem")
	if err != nil {
		return err
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	return err
}

func SignAccessToken(userId, clientId string, scope []string) (*models.AccessToken, string, error) {
	claims := &models.AccessToken{
		Sub:      userId,
		ClientId: clientId,
		Scopes:   scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ExpiryAccessAndIDToken)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(privateKey)

	return claims, tokenStr, err
}

func SignRefreshToken(userId, clientId string, scope []string, expiry time.Duration) (*models.RefreshToken, string, error) {
	claims := &models.RefreshToken{
		Sub:      userId,
		ClientId: clientId,
		Scope:    scope,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(privateKey)

	return claims, tokenStr, err
}

func SignIdToken(sub, aud, iss, nonce string, claims *models.Claims) (*models.IdToken, string, error) {
	IdToken := &models.IdToken{
		Sub:      sub,
		Aud:      aud,
		Iss:      iss,
		Nonce:    nonce,
		AuthTime: time.Now().Unix(),

		Claims: claims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ExpiryAccessAndIDToken)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, IdToken)
	tokenStr, err := token.SignedString(privateKey)

	return IdToken, tokenStr, err
}

func ParseIdtoken(tokenStr string) (*models.IdToken, error) {
	idToken := &models.IdToken{}
	token, err := jwt.ParseWithClaims(tokenStr, idToken,
		func(t *jwt.Token) (any, error) {
			return publicKey, nil
		},
	)

	if err != nil {
		return &models.IdToken{}, err
	}

	if !token.Valid {
		return &models.IdToken{}, jwt.ErrTokenInvalidClaims
	}

	return idToken, nil
}

func ParseAccessToken(tokenStr string) (*models.AccessToken, error) {
	claims := &models.AccessToken{}

	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			return publicKey, nil
		},
	)

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
			return publicKey, nil
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
