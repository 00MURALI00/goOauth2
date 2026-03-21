package service

import "github.com/00MURALI00/goOauth2/models"

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

func (s *ProviderMetadataService) GetMetadata() *models.ProviderMetadata {

	return &models.ProviderMetadata{
		Issuer:                s.issuer,
		AuthorizationEndpoint: s.issuer + "/authorize",
		TokenEndpoint:         s.issuer + "/token",

		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},

		ResponseTypesSupported: []string{
			"code",
		},

		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},

		CodeChallengeMethodsSupported: []string{
			"S256",
			"plain",
		},
	}
}