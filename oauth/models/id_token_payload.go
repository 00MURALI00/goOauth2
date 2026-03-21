package models

type IDTokenPayload struct {
	Sub      string
	Aud      string
	Iss      string
	Nonce    string
	AuthTime int64
	Exp      int64
	Iat      int64

	Claims *Claims
}