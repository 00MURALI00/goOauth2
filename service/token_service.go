package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/store"
	"github.com/00MURALI00/goOauth2/util"
)

var (
	ErrInvalidSecret      = errors.New("invalid secret")
	ErrInvalidCode        = errors.New("invalid code")
	ErrCodeExpired        = errors.New("code expired")
	ErrInvalidRedirectUri = errors.New("invalid redirect uri")
	ErrInvalidGrantType   = errors.New("invalid grant type")
)

const issuer = "http://localhost:8080"

type TokenService struct {
	store          *store.MemoryStore
	subjectService *SubjectService
	claimsService  *ClaimService
}

func NewTokenService(store *store.MemoryStore, subjectService *SubjectService, claim *ClaimService) *TokenService {
	return &TokenService{
		store:          store,
		subjectService: subjectService,
		claimsService:  claim,
	}
}

type TokenInput struct {
	GrantType    string
	ClientId     string
	ClientSecret string
	Code         string
	RedirectUri  string
	RefreshToken string
	CodeVerifier string
}

type TokenOutput struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Code         string `json:"code"`
	RedirectUri  string `json:"redirect_uri"`
	State        string `json:"state"`

	IsOIDC bool     `json:"is_oidc"`
	Scope  []string `json:"scope"`
	Nonce  string   `json:"nonce"`
}

type TokenExchangeResult struct {
	RefreshToken *models.RefreshToken
	AccessToken  *models.AccessToken

	AccessTokenString  string
	RefreshTokenString string
	IsOIDC             bool
	Nonce              string
	Scope              []string
	UserId             string
	ClientId           string

	User           *models.User
	Subject        *models.Subject
	Claims         *models.Claims
	IdTokenPayload *models.IDTokenPayload

	AuthTime int64
	Issuer   string
}

func (ts *TokenService) Token(input TokenInput) (*TokenOutput, error) {
	switch input.GrantType {
	case "authorization_code":
		return ts.tokenByCode(input)
	case "refresh_token":
		return ts.tokenByRefresh(input)
	default:
		return &TokenOutput{}, ErrInvalidGrantType
	}
}

func (ts *TokenService) ExchangeAuthorizationCode(input TokenInput, client models.Client, code models.AuthorizationCode) (*TokenExchangeResult, error) {
	_, accessTokenStr, err := util.SignAccessToken(code.UserId, client.ClientId, code.Scope)
	if err != nil {
		return nil, err
	}

	_, refreshTokenStr, err := util.SignRefreshToken(code.UserId, code.ClientId, code.Scope, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	subject, err := ts.subjectService.GetSubjectByUserId(code.UserId)
	if err != nil {
		return nil, err
	}

	claim, err := ts.claimsService.BuildClaimFromScope(subject, code.Scope)
	if err != nil {
		return nil, err
	}

	if err := ts.validatePKCE(input.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod); err != nil {
		return nil, err
	}

	ctx := ts.buildTokenContext(
		code,
		subject,
		claim,
	)

	ts.store.DeleteCode(code.Code)
	return &TokenExchangeResult{
		AccessTokenString:  accessTokenStr,
		RefreshTokenString: refreshTokenStr,

		Scope:  ctx.Scope,
		Nonce:  ctx.Nonce,
		IsOIDC: ctx.IsOIDC,

		UserId:   ctx.UserId,
		ClientId: ctx.ClientId,

		Subject: ctx.Subject,
		Claims:  ctx.Claims,

		AuthTime: ctx.AuthTime,
		Issuer:   ctx.Issuer,

		IdTokenPayload: ctx.IDTokenPayload,
	}, nil
}

// Private methods

func (s *TokenService) buildTokenContext(
	code models.AuthorizationCode,
	subject *models.Subject,
	claims *models.Claims,
) *models.TokenContext {

	ctx := &models.TokenContext{
		UserId:   code.UserId,
		ClientId: code.ClientId,

		Scope:  code.Scope,
		IsOIDC: code.IsOIDC,

		Nonce: code.Nonce,

		AuthTime: code.IssuedAt,
		Issuer:   issuer,

		Subject: subject,
		Claims:  claims,
	}

	if code.IsOIDC {

		now := time.Now()

		ctx.IDTokenPayload = &models.IDTokenPayload{
			Sub:      subject.Sub,
			Aud:      code.ClientId,
			Iss:      issuer,
			Nonce:    code.Nonce,
			AuthTime: code.IssuedAt,
			Iat:      now.Unix(),
			Exp:      now.Add(15 * time.Minute).Unix(),
			Claims:   claims,
		}
	}

	return ctx
}

func (ts *TokenService) tokenByCode(input TokenInput) (*TokenOutput, error) {
	client, err := ts.getClientAndValidate(input)
	if err != nil {
		return nil, err
	}

	code, err := ts.getCodeAndValidate(input)
	if err != nil {
		return nil, err
	}

	tokenExchangeResult, err := ts.ExchangeAuthorizationCode(input, client, code)
	if err != nil {
		return nil, err
	}

	return &TokenOutput{
		AccessToken:  tokenExchangeResult.AccessTokenString,
		RefreshToken: tokenExchangeResult.RefreshTokenString,
		Code:         code.Code,
		RedirectUri:  client.RedirectUri,
		State:        code.State,

		IsOIDC: code.IsOIDC,
		Nonce:  code.Nonce,
		Scope:  code.Scope,
	}, nil
}

func (ts *TokenService) tokenByRefresh(input TokenInput) (*TokenOutput, error) {
	client, err := ts.getClientAndValidate(input)
	if err != nil {
		return nil, err
	}

	claims, err := util.ParseRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, err
	}

	_, accessTokenStr, err := util.SignAccessToken(claims.Sub, client.ClientId, client.Scopes)
	if err != nil {
		return nil, err
	}

	_, refreshTokenStr, err := util.SignRefreshToken(claims.Sub, claims.ClientId, claims.Scope, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	return &TokenOutput{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
	}, nil
}

func (ts *TokenService) getClientAndValidate(input TokenInput) (models.Client, error) {
	client, ok := ts.store.GetClient(input.ClientId)
	if !ok {
		return models.Client{}, ErrInvalidClient
	}

	if client.ClientSecret != input.ClientSecret {
		return models.Client{}, ErrInvalidSecret
	}

	return client, nil
}

func (ts *TokenService) getCodeAndValidate(input TokenInput) (models.AuthorizationCode, error) {
	code, ok := ts.store.GetCode(input.Code)
	if !ok {
		return models.AuthorizationCode{}, ErrInvalidCode
	}

	if time.Now().After(time.Unix(code.Expiry, 0)) {
		return models.AuthorizationCode{}, ErrCodeExpired
	}

	if code.RedirectUri != input.RedirectUri {
		return models.AuthorizationCode{}, ErrInvalidRedirectUri
	}

	return code, nil
}

func (ts *TokenService) validatePKCE(verifier, challenge, method string) error {
	if challenge == "" {
		return ErrInvalidPKCE
	}

	if method != "S256" {
		return ErrInvalidPKCE
	}

	hash := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	if subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) != 1 {
		return ErrInvalidPKCE
	}

	return nil
}
