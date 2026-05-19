package services

import (
	"context"
	"errors"
	"time"

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
	AddProviderToUser(ctx context.Context, userID uuid.UUID, provider, providerID string) error
	RemoveProviderFromUser(ctx context.Context, userID uuid.UUID, provider string) error
	GetUserProviders(ctx context.Context, userID uuid.UUID) ([]models.OAuthProvider, error)
	CopyCardSet(ctx context.Context, req storage.CopyCardSetRequest) error
	SaveDeviceToken(ctx context.Context, userID uuid.UUID, deviceType, token, appVersion string) error
	GetDeviceTokens(ctx context.Context, userID uuid.UUID) ([]models.DeviceToken, error)
	DeleteDeviceToken(ctx context.Context, userID uuid.UUID, token string) error
	DeleteAllDeviceTokens(ctx context.Context, userID uuid.UUID) error
	UpdateLastActivity(ctx context.Context, id uuid.UUID) error
	GetInactiveUsers(ctx context.Context, inactiveSince time.Time, limit int) ([]models.User, error)
	UpdateNotificationSettings(ctx context.Context, id uuid.UUID, notificationEnabled bool) (*models.User, error)
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

func (s *UserService) UpdateNotificationSettings(ctx context.Context, id uuid.UUID, notificationEnabled bool) (*models.User, error) {
	user, err := s.repo.UpdateNotificationSettings(ctx, id, notificationEnabled)
	if err != nil {
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

func (s *UserService) AddProviderToUser(ctx context.Context, userID uuid.UUID, provider, providerID string) error {
	return s.repo.AddProviderToUser(ctx, userID, provider, providerID)
}

func (s *UserService) RemoveProviderFromUser(ctx context.Context, userID uuid.UUID, provider string) error {
	return s.repo.RemoveProviderFromUser(ctx, userID, provider)
}

func (s *UserService) GetUserProviders(ctx context.Context, userID uuid.UUID) ([]models.OAuthProvider, error) {
	return s.repo.GetUserProviders(ctx, userID)
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

func (s *UserService) SearchUsers(ctx context.Context, req storage.SearchUsersRequest) (*storage.SearchUsersResponse, error) {
	return s.repo.SearchUsers(ctx, req)
}

func (s *UserService) CopyCardSet(ctx context.Context, req storage.CopyCardSetRequest) error {
	return s.repo.CopyCardSet(ctx, req)
}

// SaveDeviceToken saves or updates a device token for push notifications
func (s *UserService) SaveDeviceToken(ctx context.Context, userID uuid.UUID, deviceType, token, appVersion string) error {
	return s.repo.SaveDeviceToken(ctx, userID, deviceType, token, appVersion)
}

// GetDeviceTokens returns all device tokens for a user
func (s *UserService) GetDeviceTokens(ctx context.Context, userID uuid.UUID) ([]models.DeviceToken, error) {
	return s.repo.GetDeviceTokens(ctx, userID)
}

// DeleteDeviceToken removes a device token
func (s *UserService) DeleteDeviceToken(ctx context.Context, userID uuid.UUID, token string) error {
	return s.repo.DeleteDeviceToken(ctx, userID, token)
}

// DeleteAllDeviceTokens removes all device tokens for a user (e.g., on logout)
func (s *UserService) DeleteAllDeviceTokens(ctx context.Context, userID uuid.UUID) error {
	return s.repo.DeleteAllDeviceTokens(ctx, userID)
}

func (s *UserService) UpdateLastActivity(ctx context.Context, userID uuid.UUID) error {
	return s.repo.UpdateLastActivity(ctx, userID)
}

func (s *UserService) GetInactiveUsers(ctx context.Context, inactiveSince time.Time, limit int) ([]models.User, error) {
	return s.repo.GetInactiveUsers(ctx, inactiveSince, limit)
}
