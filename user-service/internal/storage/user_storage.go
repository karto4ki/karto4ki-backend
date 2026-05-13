package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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
		if errors.Is(err, sql.ErrNoRows) {
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
		if errors.Is(err, sql.ErrNoRows) {
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
	if !errors.Is(err, sql.ErrNoRows) {
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
	if !errors.Is(err, sql.ErrNoRows) {
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	query := `
        SELECT id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
        FROM users
        WHERE username = $1
    `
	row := s.db.QueryRow(ctx, query, username)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) UpdateUser(ctx context.Context, id uuid.UUID, name, username string, notificationEnabled bool) (*models.User, error) {
	var existingID uuid.UUID
	checkQuery := `SELECT id FROM users WHERE username = $1 AND id != $2`
	err := s.db.QueryRow(ctx, checkQuery, username, id).Scan(&existingID)
	if err == nil {
		return nil, ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	query := `
        UPDATE users
        SET name = $1, username = $2, notification_enabled = $3
        WHERE id = $4
        RETURNING id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
    `
	var user models.User
	row := s.db.QueryRow(ctx, query, name, username, notificationEnabled, id)
	err = row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	res, err := s.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *UserStorage) UpdatePhoto(ctx context.Context, id uuid.UUID, photoURL string) (*models.User, error) {
	query := `
        UPDATE users SET photo_url = $1 WHERE id = $2
        RETURNING id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
    `
	var user models.User
	row := s.db.QueryRow(ctx, query, photoURL, id)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) DeletePhoto(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
        UPDATE users SET photo_url = NULL WHERE id = $1
        RETURNING id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
    `
	var user models.User
	row := s.db.QueryRow(ctx, query, id)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		&user.Provider, &user.ProviderId,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

type SearchUsersRequest struct {
	Name     *string
	Username *string
	Offset   int
	Limit    int
}

type SearchUsersResponse struct {
	Users  []models.User
	Offset int
	Count  int
}

func (s *UserStorage) SearchUsers(ctx context.Context, req SearchUsersRequest) (*SearchUsersResponse, error) {
	baseQuery := `
        SELECT id, email, name, username, photo_url, created_at, notification_enabled, provider, provider_id
        FROM users
        WHERE 1=1
    `
	countQuery := `SELECT COUNT(*) FROM users WHERE 1=1`
	args := []interface{}{}
	countArgs := []interface{}{}
	counter := 1

	if req.Name != nil && *req.Name != "" {
		baseQuery += fmt.Sprintf(" AND name ILIKE $%d", counter)
		countQuery += fmt.Sprintf(" AND name ILIKE $%d", counter)
		args = append(args, "%"+*req.Name+"%")
		countArgs = append(countArgs, "%"+*req.Name+"%")
		counter++
	}
	if req.Username != nil && *req.Username != "" {
		baseQuery += fmt.Sprintf(" AND username ILIKE $%d", counter)
		countQuery += fmt.Sprintf(" AND username ILIKE $%d", counter)
		args = append(args, "%"+*req.Username+"%")
		countArgs = append(countArgs, "%"+*req.Username+"%")
		counter++
	}

	var total int
	if err := s.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", counter, counter+1)
	args = append(args, req.Limit, req.Offset)

	rows, err := s.db.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []models.User{}
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Email, &user.Name, &user.Username,
			&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
			&user.Provider, &user.ProviderId,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return &SearchUsersResponse{
		Users:  users,
		Offset: req.Offset,
		Count:  total,
	}, nil
}
