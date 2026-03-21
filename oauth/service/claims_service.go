package service

import (
	"github.com/00MURALI00/goOauth2/oauth/models"
)

type ClaimService struct {
}

func NewClaimService() *ClaimService {
	return &ClaimService{}
}

func (cs *ClaimService) BuildClaimFromScope(subject *models.Subject, scope []string) (*models.Claims, error) {
	claim := &models.Claims{}
	for _, sc := range scope {
		switch sc {
		case "openid":
			claim.Sub = subject.Sub
		case "profile":
			claim.Name = subject.Name
		case "email":
			claim.Email = subject.Email
		default:
			return nil, ErrInvalidScope
		}
	}

	return claim, nil
}
