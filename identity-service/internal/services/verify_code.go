package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
)

type AuthVerifyRepository interface {
	FindKey(ctx context.Context, authKey uuid.UUID) (*storage.AuthData, error)
	Store(context.Context, *storage.AuthData) error
}

type AuthVerifyService struct {
	repo AuthVerifyRepository
}

func NewAuthVerifyService(repo AuthVerifyRepository) *AuthVerifyService {
	return &AuthVerifyService{
		repo: repo,
	}
}

func (s *AuthVerifyService) VerifyCode(ctx context.Context, authKey uuid.UUID, code string) error {
	data, err := s.repo.FindKey(ctx, authKey)
	if err != nil {
		if errors.Is(err, storage.ErrAuthKeyNotFound) {
			return ErrAuthKeyNotFound
		}
		return err
	}
	if data.Code != code {
		return ErrWrongCode
	}

	data.Verified = true
	if err := s.repo.Store(ctx, data); err != nil {
		return fmt.Errorf("sign up meta update failed: %s", err)
	}

	return nil
}
