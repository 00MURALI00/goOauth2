package models

type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"user_info_endpoint"`
	JwksEndpoint string `json:"jwks_uri"`

	ResponseTypesSupported []string `json:"response_types_supported"`
	SubjectTypesSupported []string `json:"subject_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenege_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
	GrantTypesSupported    []string `json:"grant_type_supported"`
	ClaimsSupported []string `json:"claims_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}