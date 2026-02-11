package services

import (
	"context"
	"errors"

	"github.com/karto4ki/karto4ki-backend/identity-service/internal/jwt"
)

var (
	ErrRefreshTokenExpired     = errors.New("refresh token expired")
	ErrRefreshTokenInvalidated = errors.New("refresh token invalidated")
	ErrInvalidJWT              = errors.New("jwt token is invalid")
	ErrInvalidTokenType        = errors.New("jwt token has invalid type")
	ErrRevokeToken             = errors.New("refresh token invalidation")
	ErrInvalidClaims           = errors.New("invalid claims")
	ErrAccessGeneration        = errors.New("access token generation failed")
	ErrRefreshGeneration       = errors.New("refresh token generation failed")
)

type RevokeRepository interface {
	Revoke(ctx context.Context, jwtToken jwt.Token) error
	IsRevoked(ctx context.Context, jwtToken jwt.Token) (bool, error)
}

type RefreshJWTService struct {
	accessConf  *jwt.Config
	refreshConf *jwt.Config
	revokeRepo  RevokeRepository
}

func NewRefreshJWTService(access, refresh *jwt.Config, revoke RevokeRepository) *RefreshJWTService {
	return &RefreshJWTService{
		accessConf:  access,
		refreshConf: refresh,
		revokeRepo:  revoke,
	}
}

func (service *RefreshJWTService) Refresh(ctx context.Context, refresh jwt.Token) (jwt.Pair, error) {
	if err := service.validate(ctx, refresh); err != nil {
		return jwt.Pair{}, err
	}

	claims, err := jwt.Parse(service.refreshConf, refresh)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return jwt.Pair{}, ErrRefreshTokenExpired
		}
		if errors.Is(err, jwt.ErrInvalidTokenType) {
			return jwt.Pair{}, ErrInvalidTokenType
		}
		return jwt.Pair{}, ErrInvalidJWT
	}

	if err := service.revokeRepo.Revoke(ctx, refresh); err != nil {
		return jwt.Pair{}, ErrRevokeToken
	}

	if claims["sub"] == nil {
		return jwt.Pair{}, ErrInvalidClaims
	}

	var pair jwt.Pair
	if pair.Access, err = jwt.Generate(service.accessConf, jwt.Claims(claims)); err != nil {
		return jwt.Pair{}, ErrAccessGeneration
	}
	if pair.Refresh, err = jwt.Generate(service.refreshConf, jwt.Claims(claims)); err != nil {
		return jwt.Pair{}, ErrRefreshGeneration
	}
	return pair, nil
}

func (service *RefreshJWTService) validate(ctx context.Context, refresh jwt.Token) error {
	revoked, err := service.revokeRepo.IsRevoked(ctx, refresh)
	if err != nil {
		return err
	}
	if revoked {
		return ErrRefreshTokenInvalidated
	}
	return err
}
