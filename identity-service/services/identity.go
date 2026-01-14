package services

import (
	"context"
	"errors"

	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
)

var (
	ErrTypeAccessTokenExpired   = errors.New("access token expired")
	ErrIncorrectGenerationToken = errors.New("failed to generate token")
)

type AuthService struct {
	userConfig     *jwt.Config
	internalConfig *jwt.Config
}

func NewAuthService(userConfig, internalConfig *jwt.Config) *AuthService {
	return &AuthService{
		userConfig:     userConfig,
		internalConfig: internalConfig,
	}
}

func (s *AuthService) Authenticate(ctx context.Context, token jwt.Token) (jwt.Token, error) {
	claims, err := jwt.Parse(s.userConfig, token)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return "", ErrTypeAccessTokenExpired
		case errors.Is(err, jwt.ErrInvalidTokenType):
			return "", ErrInvalidTokenType
		default:
			return "", ErrInvalidJWT
		}
	}

	internalClaims := s.extractInternalClaims(jwt.Claims(claims))

	internalToken, err := jwt.Generate(s.internalConfig, internalClaims)
	if err != nil {
		return "", ErrIncorrectGenerationToken
	}

	return internalToken, nil
}

func (s *AuthService) extractInternalClaims(userClaims jwt.Claims) jwt.Claims {
	internalClaims := make(jwt.Claims)
	if sub, ok := userClaims["sub"]; ok {
		internalClaims["sub"] = sub
	}

	if name, ok := userClaims["name"]; ok {
		internalClaims["name"] = name
	}

	if username, ok := userClaims["username"]; ok {
		internalClaims["username"] = username
	}

	if s.internalConfig.Issuer != "" {
		internalClaims["iss"] = s.internalConfig.Issuer
	}

	if len(s.internalConfig.Audience) > 0 {
		internalClaims["aud"] = s.internalConfig.Audience
	}

	internalClaims["typ"] = "internal"

	return internalClaims
}

func (s *AuthService) ValidateInternalToken(ctx context.Context, token jwt.Token) (jwt.Claims, error) {
	claims, err := jwt.Parse(s.internalConfig, jwt.Token(token))
	if err != nil {
		return nil, ErrInvalidJWT
	}

	if typ, ok := claims["typ"]; !ok || typ != "internal" {
		return nil, ErrInvalidTokenType
	}

	return jwt.Claims(claims), nil
}
