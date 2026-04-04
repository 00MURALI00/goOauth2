package models

import "github.com/golang-jwt/jwt/v5"

type AccessToken struct {
	ID       string   `json:id`
	Sub      string   `json:"sub"`
	ClientId string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	SId      string   `json:"sid"`

	jwt.RegisteredClaims
}
