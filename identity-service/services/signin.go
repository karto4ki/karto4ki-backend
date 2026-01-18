package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/storage"
)

var (
	ErrFailedFindSignInKey   = errors.New("failed to find sign in key")
	ErrSignInKeyNotFound     = errors.New("sign in key was not found")
	ErrWrongCode             = errors.New("wrong code")
	ErrRemoveSignInKeyFailed = errors.New("failed to remove signin key")
)

type SignInRepository interface {
	FindKey(ctx context.Context, signInKey uuid.UUID) (*storage.SignInData, error)
	Remove(ctx context.Context, signInKey uuid.UUID) error
}

type SignInService struct {
	signInRepo  SignInRepository
	accessConf  *jwt.Config
	refreshConf *jwt.Config
}

func NewSignInService(repo SignInRepository, accesConf, refreshConf *jwt.Config) *SignInService {
	return &SignInService{
		signInRepo:  repo,
		accessConf:  accesConf,
		refreshConf: refreshConf,
	}
}

func (s *SignInService) SignIn(ctx context.Context, signinKey uuid.UUID, code string) (jwt.Pair, error) {
	data, err := s.signInRepo.FindKey(ctx, signinKey)
	if err != nil {
		if !errors.Is(err, storage.ErrSignInKeyNotFound) {
			return jwt.Pair{}, ErrFailedFindSignInKey
		} else {
			return jwt.Pair{}, ErrSignInKeyNotFound
		}
	}
	if data.Code != code {
		return jwt.Pair{}, ErrWrongCode
	}

	claims := jwt.Claims{
		"sub":      data.UserId,
		"name":     data.Name,
		"username": data.Username,
	}
	var pair jwt.Pair
	if pair.Access, err = jwt.Generate(s.accessConf, claims); err != nil {
		return jwt.Pair{}, ErrAccessGeneration
	}
	if pair.Refresh, err = jwt.Generate(s.refreshConf, claims); err != nil {
		return jwt.Pair{}, ErrRefreshGeneration
	}
	if err := s.signInRepo.Remove(ctx, signinKey); err != nil {
		return jwt.Pair{}, ErrRemoveSignInKeyFailed
	}
	return pair, nil
}
