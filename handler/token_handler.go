package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/00MURALI00/goOauth2/service"
)

type TokenHandler struct {
	tokenService *service.TokenService
}

func NewTokenHandler(
	tokenService *service.TokenService,
) *TokenHandler {

	return &TokenHandler{
		tokenService: tokenService,
	}
}

func (h *TokenHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	input := service.TokenInput{

		GrantType: r.Form.Get("grant_type"),

		Code: r.Form.Get("code"),

		RedirectUri: r.Form.Get("redirect_uri"),

		ClientId:     r.Form.Get("client_id"),
		ClientSecret: r.Form.Get("client_secret"),

		CodeVerifier: r.Form.Get("code_verifier"),

		RefreshToken: r.Form.Get("refresh_token"),
	}
	fmt.Println("GRant Type: ", r.Form.Get("grant_type"))
	output, err := h.tokenService.Token(input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(output); err != nil {
    http.Error(w, "Failed to encode response", http.StatusInternalServerError)
    return
}
}
