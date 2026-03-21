package service

import (
	"github.com/00MURALI00/goOauth2/oauth/models"
	"github.com/00MURALI00/goOauth2/util"
)

type TokenInfoService struct {
	subjectService *SubjectService
	claimsService  *ClaimService
}

func NewTokenInfoService(subjectService *SubjectService, claimsService *ClaimService) *TokenInfoService {
	return &TokenInfoService{
		subjectService: subjectService,
		claimsService:  claimsService,
	}
}

func (ts *TokenInfoService) GetAccessTokenContext(token string) (*models.TokenContext, error) {
	claims, err := util.ParseAccessToken(token)
	if err != nil {
		return nil, err
	}
	subject, err := ts.subjectService.GetSubjectByUserId(claims.Sub)
	if err != nil {
		return nil, err
	}
	claimsObj, err := ts.claimsService.BuildClaimFromScope(subject, claims.Scopes)
	if err != nil {
		return nil, err
	}

	return &models.TokenContext{
		UserId:   claims.Sub,
		ClientId: claims.ClientId,
		Scope:    claims.Scopes,
		Issuer:   claims.Issuer,
		Subject:  subject,
		Claims:   claimsObj,
	}, nil
}
