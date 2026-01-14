package services

import (
	"context"
	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
)

type SignoutService struct {
	refreshConf *jwt.Config
	revokeRepo  RevokeRepository
}

func NewSignOutService(refreshConf *jwt.Config, revokeRepo RevokeRepository) *SignoutService {
	return &SignoutService{
		refreshConf: refreshConf,
		revokeRepo:  revokeRepo,
	}
}

func (s SignoutService) SignOut(ctx context.Context, refreshToken string) error {
	token := jwt.Token(refreshToken)
	claims, err := jwt.Parse(s.refreshConf, token)
	if err != nil {
		return ErrInvalidJWT
	}

	if typ, ok := claims["typ"]; !ok || typ != "refresh" {
		return ErrInvalidTokenType
	}

	if err := s.revokeRepo.Revoke(ctx, token); err != nil {
		return ErrRevokeToken
	}

	return nil
}
