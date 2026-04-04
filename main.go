package main

import (
	"fmt"
	"net/http"

	"github.com/00MURALI00/goOauth2/handler"
	"github.com/00MURALI00/goOauth2/middleware"
	"github.com/00MURALI00/goOauth2/models"
	"github.com/00MURALI00/goOauth2/service"
	"github.com/00MURALI00/goOauth2/store"
)

func hello(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	fmt.Printf("Code: %s\n",query.Get("code"))
	w.Write([]byte("hello"))
}

func main() {
	issuer := "http://localhost:3000"

	// Store
	memStore := store.NewMemoryStore()
	memStore.SaveClient(models.Client{
		ClientId:    "test-client",
		RedirectUri: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "profile", "email"},
	})

	// Services
	loginService := service.NewLoginService(memStore)
	subjectService := service.NewSubjectService(memStore)
	claimsService := service.NewClaimService()
	authorizeService := service.NewAuthorizeService(memStore)
	tokenService := service.NewTokenService(memStore, subjectService, claimsService)
	tokenInfoService := service.NewTokenInfoService(subjectService, claimsService)
	metadataService := service.NewProviderMetadataService(issuer)
	signupService := service.NewSignupService(memStore)

	// Handlers
	authorizeHandler := handler.NewAuthorizeHandler(authorizeService, loginService)
	tokenHandler := handler.NewTokenHandler(tokenService)
	tokenInfoHandler := handler.NewTokenInfoHandler(tokenInfoService)
	metadataHandler := handler.NewOauthMetadataHandler(metadataService)
	SignupHandler := handler.NewSignupHandler(signupService)

	// Routes
	http.Handle("POST /authorize", middleware.Logger(http.HandlerFunc(authorizeHandler.Handle)))
	http.Handle("POST /token", middleware.Logger(http.HandlerFunc(tokenHandler.Handle)))
	http.Handle("GET /tokeninfo", middleware.Logger(http.HandlerFunc(tokenInfoHandler.Handle)))
	http.Handle("POST /signup", middleware.Logger(http.HandlerFunc(SignupHandler.Handle)))
	http.Handle("GET /userinfo", middleware.Logger(http.HandlerFunc(tokenInfoHandler.Handle)))
	http.Handle("GET /jwks.json", middleware.Logger(http.HandlerFunc(metadataHandler.Handle)))
	http.Handle("GET /.well-known/openid-configuration", middleware.Logger(http.HandlerFunc(metadataHandler.Handle)))
	http.Handle("GET /callback", http.HandlerFunc(hello))

	// Server
	http.ListenAndServe(":3000", nil)
}
