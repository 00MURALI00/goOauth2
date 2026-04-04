package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/00MURALI00/goOauth2/service"
)

type AuthorizeHandler struct {
	authorizeServer *service.AuthorizeService
	loginService    *service.LoginService
}

func NewAuthorizeHandler(authorizeServive *service.AuthorizeService, loginService *service.LoginService) *AuthorizeHandler {
	return &AuthorizeHandler{
		authorizeServer: authorizeServive,
		loginService:    loginService,
	}
}

type Request struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	ClientId            string `json:"client_id"`
	RedirectUri         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func (a *AuthorizeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	req := Request{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error Decoding the Payload", 401)
		return
	}

	user, err := a.loginService.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	input := service.AuthorizeInput{
		ClientId:            req.ClientId,
		RedirectUri:         req.RedirectUri,
		ResponseType:        req.ResponseType,
		Scope:               strings.Split(req.Scope, " "),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		UserId:              user.UserId,
	}

	code, err := a.authorizeServer.Authorize(input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	redirect := code.RedirectUri +
		"?code=" + code.Code

	if code.State != "" {
		redirect += "&state=" + code.State
	}

	http.Redirect(w, r, redirect, http.StatusFound)
}
