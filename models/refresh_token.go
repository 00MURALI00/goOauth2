package models

import "github.com/golang-jwt/jwt/v5"

type RefreshToken struct {
	Sub      string `json:"sub"`
	ClientId string `json:"client_id"`
	Scope []string `json:"scope"`

	jwt.RegisteredClaims
}
