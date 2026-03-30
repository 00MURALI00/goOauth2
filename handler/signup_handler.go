package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/service"
)

type SignupHandler struct {
	signupService *service.SignupService
}

func NewSignupHandler(signupService *service.SignupService) *SignupHandler {
	return &SignupHandler{
		signupService: signupService,
	}
}

func (s *SignupHandler) Handle(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid Body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = s.signupService.SignupUser(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	msg := struct {
		Message  string `json:"message"`
		Username string `json:"username"`
		UserId   string `json:"user_id"`
		Email    string `json:"email"`
	}{
		Message:  "User Signed up",
		Username: user.Username,
		UserId:   user.UserId,
		Email:    user.Email,
	}
	fmt.Println("User Signed up")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(msg); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
