package models

type ProviderMetadata struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string

	ScopesSupported        []string
	ResponseTypesSupported []string
	GrantTypesSupported    []string

	CodeChallengeMethodsSupported []string
}