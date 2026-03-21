package handler

import (
	"log"
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

func (a *AuthorizeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	userId := q.Get("user_id")
	password := q.Get("password")

	user, err := a.loginService.Login(userId, password)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	input := service.AuthorizeInput{
		ClientId:     q.Get("client_id"),
		RedirectUri:  q.Get("redirect_uri"),
		ResponseType: q.Get("response_type"),
		Scope:        strings.Split(q.Get("scope"), " "),
		State:        q.Get("state"),
		Nonce:        q.Get("nonce"),
		UserId:       user.UserId,

		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
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
