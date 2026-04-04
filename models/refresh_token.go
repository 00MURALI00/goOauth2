package models

import "github.com/golang-jwt/jwt/v5"

type RefreshToken struct {
	ID       string   `json:"id"`
	Sub      string   `json:"sub"`
	ClientId string   `json:"client_id"`
	Scope    []string `json:"scope"`
	SId      string   `json:"sid"`

	jwt.RegisteredClaims
}
