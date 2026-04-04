package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/00MURALI00/goOauth2/service"
)

type LogoutHandler struct {
	logoutService service.LogoutService
}

func NewLogoutHandler(logoutService *service.LogoutService) *LogoutHandler {
	return &LogoutHandler{
		logoutService: *logoutService,
	}
}

func (ls *LogoutHandler) Handler(w http.ResponseWriter, r *http.Request) {
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
	ls.logoutService.Logout(token)

	msg := struct {
		Message  string `json:"message"`
	}{
		Message:  "User Logged Out",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}
