package models

type IDTokenPayload struct {
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Iss      string `json:"iss"`
	Nonce    string `json:"nonce"`
	AuthTime int64 `json:"auth_time"`
	Exp      int64 `json:"exp"`
	Iat      int64 `json:"iat"`

	Claims *Claims
}