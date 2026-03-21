package models

import "github.com/golang-jwt/jwt/v5"

type AccessToken struct {
	Sub      string `json:"sub"`
	ClientId string `json:"client_id"`
	Scopes   []string `json:"scopes"`

	jwt.RegisteredClaims
}
