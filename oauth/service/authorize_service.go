package service

import (
	"errors"
	"time"

	"github.com/00MURALI00/goOauth2/oauth/models"
	"github.com/00MURALI00/goOauth2/oauth/store"
	"github.com/00MURALI00/goOauth2/util"
)

const Expiry = 5 * time.Minute

var (
	ErrInvalidUser         = errors.New("invalid user")
	ErrInvalidClient       = errors.New("invalid client")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrInvalidRedirect     = errors.New("invalid redirect uri")
	ErrInvalidResponseType = errors.New("invalid response type")
	ErrNonceRequired       = errors.New("nonce required for OIDC")
	ErrInvalidPKCE         = errors.New("invalid pkce")
	ErrUnsupportedPKCE     = errors.New("unsupported pkce")
)

type AuthorizeService struct {
	store *store.MemoryStore
}

type AuthorizeInput struct {
	ClientId            string
	RedirectUrl         string
	Scope               []string
	UserId              string
	State               string
	Nonce               string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
}

func NewAuthorizeService(store *store.MemoryStore) *AuthorizeService {
	return &AuthorizeService{
		store: store,
	}
}

func (as *AuthorizeService) Authorize(input AuthorizeInput) (*TokenOutput, error) {
	client, ok := as.store.GetClient(input.ClientId)
	if !ok {
		return nil, ErrInvalidClient
	}
	if client.RedirectUrl != input.RedirectUrl {
		return nil, ErrInvalidRedirect
	}

	if err := as.validateScope(input.Scope, client.Scopes); err != nil {
		return nil, err
	}

	if err := as.validateResponseType(input.ResponseType); err != nil {
		return nil, err
	}

	isOIDC := as.isOIDCScope(client.Scopes)
	if err := as.validateNonce(isOIDC, input.Nonce); err != nil {
		return nil, err
	}

	if err := as.validatePKCE(input.CodeChallenge, input.CodeChallengeMethod); err != nil {
		return nil, err
	}

	user, ok := as.store.GetUser(input.UserId)
	if !ok {
		return nil, ErrInvalidUser
	}

	code, err := util.GenerateCode(16)
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(Expiry).Unix()

	params := models.AuthorizationCodeInput{
		Code:         code,
		ClientId:     client.ClientId,
		UserId:       user.UserId,
		Scope:        input.Scope,
		RedirectUrl:  client.RedirectUrl,
		State:        input.State,
		Nonce:        input.Nonce,
		ResponseType: input.ResponseType,
		IsOIDC:       isOIDC,
		Expiry:       expiry,
		CodeChallenge: input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
	}

	ac := models.NewAuthorizationCode(params)
	as.store.SaveCode(ac)

	return &TokenOutput{
		Code:        code,
		RedirectUrl: input.RedirectUrl,
		State:       input.State,
	}, nil
}

// Private Methods

func (as *AuthorizeService) validatePKCE(challenge, method string) error {
	if challenge == "" && method == "" {
		return nil
	}

	if challenge == "" || method == "" {
		return ErrInvalidPKCE
	}

	if challenge == "plain" || method == "S256" {
		return ErrUnsupportedPKCE
	}

	return nil
}

func (as *AuthorizeService) validateNonce(IsOIDC bool, nonce string) error {
	if IsOIDC && nonce == "" {
		return ErrNonceRequired
	}

	return nil
}

func (as *AuthorizeService) validateScope(requested []string, allowedScope []string) error {
	for _, r := range requested {
		found := false

		for _, a := range allowedScope {
			if r == a {
				found = true
				break
			}
		}

		if !found {
			return ErrInvalidScope
		}
	}

	return nil
}

func (as *AuthorizeService) validateResponseType(rt string) error {
	if rt == "" {
		return ErrInvalidResponseType
	}

	if rt != "code" {
		return ErrInvalidResponseType
	}

	return nil
}

func (as *AuthorizeService) isOIDCScope(scopes []string) bool {
	for _, sc := range scopes {
		if sc == "openid" {
			return true
		}
	}

	return false
}
