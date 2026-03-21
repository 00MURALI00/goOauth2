package models

type Client struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUrl  string `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}
