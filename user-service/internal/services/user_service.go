package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrAlreadyExists = errors.New("user already exists")
)

type UserRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByProvider(ctx context.Context, provider, providerID string) (*models.User, error)
	CreateUserWithEmail(ctx context.Context, email, name, username string) (*models.User, error)
	CreateUserWithProvider(ctx context.Context, provider, providerID, name, username string) (*models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) // опционально
}

type UserService struct {
	repo UserRepository
}

func NewUserService(repo UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) GetUserByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	user, err := s.repo.GetUserByProvider(ctx, provider, providerID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) CreateUserWithEmail(ctx context.Context, email, name, username string) (*models.User, error) {
	user, err := s.repo.CreateUserWithEmail(ctx, email, name, username)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) CreateUserWithProvider(ctx context.Context, provider, providerID, name, username string) (*models.User, error) {
	user, err := s.repo.CreateUserWithProvider(ctx, provider, providerID, name, username)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return user, nil
}
