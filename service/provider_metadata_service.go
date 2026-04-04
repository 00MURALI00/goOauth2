package service

import (
	"fmt"

	"github.com/00MURALI00/goOauth2/models"
)

type ProviderMetadataService struct {
	issuer string
}

func NewProviderMetadataService(
	issuer string,
) *ProviderMetadataService {

	return &ProviderMetadataService{
		issuer: issuer,
	}
}

func (s *ProviderMetadataService) GetOpenIdConfigMetadata() *models.ProviderMetadata {

	return &models.ProviderMetadata{
		Issuer:                s.issuer,
		AuthorizationEndpoint: s.issuer + "/authorize",
		TokenEndpoint:         s.issuer + "/token",
		UserInfoEndpoint:      s.issuer + "/userinfo",
		JwksEndpoint:          s.issuer + "/jwks.json",

		ResponseTypesSupported: []string{
			"code",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},
		ClaimsSupported: []string{
			"sub",
			"name",
			"email",
			"iss",
			"aud",
			"iat",
			"exp",
		},
		IdTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
	}
}

func (s *ProviderMetadataService) GetJwksJsonMetaData() *models.JWKS {
	jwks := models.JWKS{}
	err := jwks.GetPublicKeyData()
	fmt.Printf("%v /n", err)
	return &jwks
}
