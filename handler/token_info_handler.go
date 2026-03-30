package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/00MURALI00/goOauth2/service"
)

type TokenInfoHandler struct {
	tokenInfoService *service.TokenInfoService
}

func NewTokenInfoHandler(
	tokenInfoService *service.TokenInfoService,
) *TokenInfoHandler {

	return &TokenInfoHandler{
		tokenInfoService: tokenInfoService,
	}
}

func (h *TokenInfoHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {

	auth := r.Header.Get("Authorization")

	if auth == "" {
		http.Error(w, "missing authorization", http.StatusBadRequest)
		return
	}

	var token string

	_, err := fmt.Sscanf(auth, "Bearer %s", &token)
	if err != nil {
		http.Error(w, "invalid authorization", http.StatusBadRequest)
		return
	}

	cxt, err := h.tokenInfoService.GetAccessTokenContext(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(cxt); err != nil {
    http.Error(w, "Failed to encode response", http.StatusInternalServerError)
    return
}
}