package models

type TokenContext struct {
	UserId   string `json:"user_id"`
	ClientId string `json:"client_id"`

	Scope  []string `json:"scope"`
	IsOIDC bool     `json:"is_oidc"`

	Nonce string `json:"nonce"`

	AuthTime int64  `json:"auth_time"`
	Issuer   string `json:"iss"`

	Subject *Subject `json:"sub"`
	Claims  *Claims  `json:"claims"`

	IDTokenPayload *IDTokenPayload
}
