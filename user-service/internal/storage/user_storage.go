package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/karto4ki/karto4ki-backend/shared/postgres"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/models"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

type UserStorage struct {
	db postgres.SQLer
}

func NewUserStorage(db postgres.SQLer) *UserStorage {
	return &UserStorage{db: db}
}

func (s *UserStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	query := `
        SELECT id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
        FROM users
        WHERE email = $1
    `
	row := s.db.QueryRow(ctx, query, email)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) GetUserByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	var user models.User
	query := `
        SELECT id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
        FROM users
        WHERE provider = $1 AND provider_id = $2
    `
	row := s.db.QueryRow(ctx, query, provider, providerID)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) CreateUserWithEmail(ctx context.Context, email, name, username string) (*models.User, error) {
	var existingID uuid.UUID
	checkQuery := `SELECT id FROM users WHERE username = $1 OR email = $2`
	err := s.db.QueryRow(ctx, checkQuery, username, email).Scan(&existingID)
	if err == nil {
		return nil, ErrAlreadyExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	user := &models.User{
		ID:                  uuid.New(),
		Email:               &email,
		Name:                name,
		Username:            username,
		CreatedAt:           time.Now(),
		NotificationEnabled: true,
		Provider:            nil,
		ProviderId:          nil,
		PhotoURL:            nil,
	}

	query := `
        INSERT INTO users (id, email, name, username, created_at, notification_enabled)
        VALUES ($1, $2, $3, $4, $5, $6)
    `
	_, err = s.db.Exec(ctx, query,
		user.ID, user.Email, user.Name, user.Username,
		user.CreatedAt, user.NotificationEnabled,
	)
	if err != nil {
		return nil, ErrAlreadyExists
	}
	return user, nil
}

func (s *UserStorage) CreateUserWithProvider(ctx context.Context, provider, providerID, name, username string) (*models.User, error) {
	var existingID uuid.UUID
	checkQuery := `SELECT id FROM users WHERE username = $1`
	err := s.db.QueryRow(ctx, checkQuery, username).Scan(&existingID)
	if err == nil {
		return nil, ErrAlreadyExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	user := &models.User{
		ID:                  uuid.New(),
		Email:               nil,
		Name:                name,
		Username:            username,
		CreatedAt:           time.Now(),
		NotificationEnabled: true,
		Provider:            &provider,
		ProviderId:          &providerID,
		PhotoURL:            nil,
	}

	query := `
        INSERT INTO users (id, name, username, created_at, notification_enabled, provider, provider_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	_, err = s.db.Exec(ctx, query,
		user.ID, user.Name, user.Username,
		user.CreatedAt, user.NotificationEnabled,
		user.Provider, user.ProviderId,
	)
	if err != nil {
		return nil, ErrAlreadyExists
	}
	return user, nil
}

func (s *UserStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	query := `
        SELECT id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
        FROM users WHERE id = $1
    `
	row := s.db.QueryRow(ctx, query, id)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}
