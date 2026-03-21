package models

type TokenContext struct {
	UserId   string
	ClientId string

	Scope  []string
	IsOIDC bool

	Nonce string

	AuthTime int64
	Issuer   string

	Subject *Subject
	Claims  *Claims

	IDTokenPayload *IDTokenPayload
}
