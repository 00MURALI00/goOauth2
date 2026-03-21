package main

import (
	"net/http"

	"github.com/00MURALI00/goOauth2/handler"
	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/service"
	"github.com/00MURALI00/goOauth2/store"
)

func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
}

func main() {
	issuer := "http://localhost:8080"

	// Store
	memStore := store.NewMemoryStore()
	memStore.SaveClient(models.Client{
		ClientId:    "test-client",
		RedirectUri: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile", "email"},
	})

	memStore.SaveUserById(models.User{
		UserId:   "user1",
		Username: "user1",
		Password: "123",
	})

	// Services
	loginService := service.NewLoginService(memStore)
	subjectService := service.NewSubjectService(memStore)
	claimsService := service.NewClaimService()
	authorizeService := service.NewAuthorizeService(memStore)
	tokenService := service.NewTokenService(memStore, subjectService, claimsService)
	tokenInfoService := service.NewTokenInfoService(subjectService, claimsService)
	metadataService := service.NewProviderMetadataService(issuer)

	// Handlers
	authorizeHandler := handler.NewAuthorizeHandler(authorizeService, loginService)
	tokenHandler := handler.NewTokenHandler(tokenService)
	tokenInfoHandler := handler.NewTokenInfoHandler(tokenInfoService)
	metadataHandler := handler.NewMetadataHandler(metadataService)

	// Routes
	http.Handle("GET /authorize", handler.Logger(http.HandlerFunc(authorizeHandler.Handle)))
	http.Handle("POST /token", handler.Logger(http.HandlerFunc(tokenHandler.Handle)))
	http.Handle("GET /tokeninfo", handler.Logger(http.HandlerFunc(tokenInfoHandler.Handle)))
	http.Handle("GET /.well-known/oauth-authorization-server", handler.Logger(http.HandlerFunc(metadataHandler.Handle)))
	http.Handle("GET /callback", http.HandlerFunc(hello))

	// Server
	http.ListenAndServe(":8080", nil)
}
