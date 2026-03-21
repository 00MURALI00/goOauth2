package models

import "time"

type AuthorizationCode struct {
	Code                string   `json:"code"`
	ClientId            string   `json:"client_id"`
	UserId              string   `json:"user_id"`
	Scope               []string `json:"scopes"`
	RedirectUri         string   `json:"redirect_uri"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce"`
	ResponseType        string   `json:"reponse_type"`
	IsOIDC              bool     `json:"is_oidc"`
	IssuedAt            int64    `json:"issued_at"`
	Expiry              int64    `json:"expiry"`
	CodeChallenge       string   `json:"code_challange"`
	CodeChallengeMethod string   `json:"code_challange_method"`
}

type AuthorizationCodeInput struct {
	Code                string
	ClientId            string
	UserId              string
	Scope               []string
	RedirectUri         string
	State               string
	Nonce               string
	ResponseType        string
	IsOIDC              bool
	IssuedAt            int64
	Expiry              int64
	CodeChallenge       string
	CodeChallengeMethod string
}

func NewAuthorizationCode(input AuthorizationCodeInput) AuthorizationCode {

	return AuthorizationCode{
		Code:                input.Code,
		ClientId:            input.ClientId,
		UserId:              input.UserId,
		Scope:               input.Scope,
		RedirectUri:         input.RedirectUri,
		State:               input.State,
		Nonce:               input.Nonce,
		ResponseType:        input.ResponseType,
		IsOIDC:              input.IsOIDC,
		Expiry:              input.Expiry,
		IssuedAt:            time.Now().Unix(),
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
	}
}
