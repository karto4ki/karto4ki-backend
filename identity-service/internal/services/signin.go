package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
)

var (
	ErrFailedFindAuthKey     = errors.New("failed to find sign in key")
	ErrAuthKeyNotFound       = errors.New("sign in key was not found")
	ErrWrongCode             = errors.New("wrong code")
	ErrRemoveAuthKeyFailed   = errors.New("failed to remove signin key")
	ErrMissingRequiredFields = errors.New("name and username are required for new user")
)

type SignInRepository interface {
	FindKey(ctx context.Context, signInKey uuid.UUID) (*storage.AuthData, error)
	Remove(ctx context.Context, signInKey uuid.UUID) error
}

type SignInService struct {
	signInRepo  SignInRepository
	accessConf  *jwt.Config
	refreshConf *jwt.Config
	userService userservice.UserServiceClient
}

func NewSignInService(repo SignInRepository, accessConf, refreshConf *jwt.Config) *SignInService {
	return &SignInService{
		signInRepo:  repo,
		accessConf:  accessConf,
		refreshConf: refreshConf,
	}
}

func (s *SignInService) SignIn(ctx context.Context, signinKey uuid.UUID, code string) (jwt.Pair, error) {
	data, err := s.signInRepo.FindKey(ctx, signinKey)
	if err != nil {
		if errors.Is(err, storage.ErrAuthKeyNotFound) {
			return jwt.Pair{}, ErrAuthKeyNotFound
		}
		return jwt.Pair{}, ErrFailedFindAuthKey
	}
	if data.Code != code {
		return jwt.Pair{}, ErrWrongCode
	}
	if data.UserId == uuid.Nil {
		return jwt.Pair{}, ErrUserNotFound
	}

	if err := s.signInRepo.Remove(ctx, signinKey); err != nil {
		return jwt.Pair{}, ErrRemoveAuthKeyFailed
	}

	claims := jwt.Claims{
		"sub":      data.UserId.String(),
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
	return pair, nil
}
