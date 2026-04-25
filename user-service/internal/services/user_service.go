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
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	UpdateUser(ctx context.Context, id uuid.UUID, name, username string, notificationEnabled bool) (*models.User, error)
	DeleteUser(ctx context.Context, id uuid.UUID) error
	UpdatePhoto(ctx context.Context, id uuid.UUID, photoURL string) (*models.User, error)
	DeletePhoto(ctx context.Context, id uuid.UUID) (*models.User, error)
	SearchUsers(ctx context.Context, req storage.SearchUsersRequest) (*storage.SearchUsersResponse, error)
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

func (s *UserService) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) UpdateUser(ctx context.Context, id uuid.UUID, name, username string, notificationEnabled bool) (*models.User, error) {
	user, err := s.repo.UpdateUser(ctx, id, name, username, notificationEnabled)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			return nil, ErrAlreadyExists
		}
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	err := s.repo.DeleteUser(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func (s *UserService) UpdatePhoto(ctx context.Context, id uuid.UUID, photoURL string) (*models.User, error) {
	user, err := s.repo.UpdatePhoto(ctx, id, photoURL)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) DeletePhoto(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := s.repo.DeletePhoto(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *UserService) SearchUsers(ctx context.Context, req storage.SearchUsersRequest) (*storage.SearchUsersResponse, error) {
	return s.repo.SearchUsers(ctx, req)
}

func (s *UserService) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	_, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
