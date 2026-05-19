package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
		SELECT id, email, name, username, photo_url, created_at, notification_enabled
		FROM users
		WHERE email = $1
	`
	row := s.db.QueryRow(ctx, query, email)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) getUserProviders(ctx context.Context, userID uuid.UUID) ([]models.OAuthProvider, error) {
	query := `
		SELECT id, user_id, provider, provider_id, created_at
		FROM user_providers
		WHERE user_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []models.OAuthProvider
	for rows.Next() {
		var p models.OAuthProvider
		err := rows.Scan(&p.ID, &p.UserID, &p.Provider, &p.ProviderID, &p.CreatedAt)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}

	return providers, rows.Err()
}

func (s *UserStorage) GetUserByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	// Ищем в таблице user_providers
	var userID uuid.UUID
	providerQuery := `SELECT user_id FROM user_providers WHERE provider = $1 AND provider_id = $2`
	err := s.db.QueryRow(ctx, providerQuery, provider, providerID).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем пользователя
	return s.GetUserByID(ctx, userID)
}

func (s *UserStorage) AddProviderToUser(ctx context.Context, userID uuid.UUID, provider, providerID string) error {
	// Проверка: не привязан ли уже такой провайдер этому пользователю
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM user_providers WHERE user_id = $1 AND provider = $2 AND provider_id = $3)`
	err := s.db.QueryRow(ctx, checkQuery, userID, provider, providerID).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return nil // Уже привязан
	}

	// Проверка: не привязан ли такой provider_id к другому пользователю
	var otherUserExists bool
	otherQuery := `SELECT EXISTS(SELECT 1 FROM user_providers WHERE provider = $1 AND provider_id = $2 AND user_id != $3)`
	err = s.db.QueryRow(ctx, otherQuery, provider, providerID, userID).Scan(&otherUserExists)
	if err != nil {
		return err
	}
	if otherUserExists {
		return ErrAlreadyExists // Этот provider_id уже у другого пользователя
	}

	// Добавляем провайдера
	query := `
		INSERT INTO user_providers (id, user_id, provider, provider_id, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = s.db.Exec(ctx, query, uuid.New(), userID, provider, providerID, time.Now())
	return err
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
		Providers:           []models.OAuthProvider{},
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
		return nil, err
	}

	return user, nil
}

func (s *UserStorage) CreateUserWithProvider(ctx context.Context, provider, providerID, name, username string) (*models.User, error) {
	// Проверка: не существует ли уже пользователь с таким provider_id
	var existingID uuid.UUID
	checkQuery := `SELECT user_id FROM user_providers WHERE provider = $1 AND provider_id = $2`
	err := s.db.QueryRow(ctx, checkQuery, provider, providerID).Scan(&existingID)
	if err == nil {
		return nil, ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	userID := uuid.New()
	user := &models.User{
		ID:                  userID,
		Email:               nil,
		Name:                name,
		Username:            username,
		CreatedAt:           time.Now(),
		NotificationEnabled: true,
		Providers:           []models.OAuthProvider{},
	}

	// Вставляем пользователя
	insertUser := `
		INSERT INTO users (id, name, username, created_at, notification_enabled)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = s.db.Exec(ctx, insertUser,
		user.ID, user.Name, user.Username,
		user.CreatedAt, user.NotificationEnabled,
	)
	if err != nil {
		return nil, err
	}

	// Вставляем провайдера
	insertProvider := `
		INSERT INTO user_providers (id, user_id, provider, provider_id, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	providerID_uuid := uuid.New()
	_, err = s.db.Exec(ctx, insertProvider, providerID_uuid, user.ID, provider, providerID, time.Now())
	if err != nil {
		// Откат: удаляем пользователя
		_, _ = s.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID)
		return nil, err
	}

	// Добавляем провайдера в список
	user.Providers = append(user.Providers, models.OAuthProvider{
		ID:         providerID_uuid,
		UserID:     user.ID,
		Provider:   provider,
		ProviderID: providerID,
		CreatedAt:  time.Now(),
	})

	return user, nil
}

func (s *UserStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, email, name, username, photo_url, created_at, notification_enabled
		FROM users
		WHERE id = $1
	`
	row := s.db.QueryRow(ctx, query, id)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, email, name, username, photo_url, created_at, notification_enabled
		FROM users
		WHERE username = $1
	`
	row := s.db.QueryRow(ctx, query, username)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) UpdateLastActivity(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET last_activity_at = NOW()
		WHERE id = $1
	`
	_, err := s.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("update last activity: %w", err)
	}
	return nil
}

func (s *UserStorage) GetInactiveUsers(ctx context.Context, inactiveSince time.Time, limit int) ([]models.User, error) {
	query := `
		SELECT id, email, name, username, photo_url, created_at, notification_enabled, last_activity_at
		FROM users
		WHERE last_activity_at < $1
		  AND notification_enabled = true
		ORDER BY last_activity_at ASC
		LIMIT $2
	`
	rows, err := s.db.Query(ctx, query, inactiveSince, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Email, &user.Name, &user.Username,
			&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
			&user.LastActivityAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (s *UserStorage) UpdateUser(ctx context.Context, id uuid.UUID, name, username string, notificationEnabled bool) (*models.User, error) {
	query := `
		UPDATE users
		SET name = $2, username = $3, notification_enabled = $4
		WHERE id = $1
		RETURNING id, email, name, username, photo_url, created_at, notification_enabled
	`
	var user models.User
	row := s.db.QueryRow(ctx, query, id, name, username, notificationEnabled)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) UpdateNotificationSettings(ctx context.Context, id uuid.UUID, notificationEnabled bool) (*models.User, error) {
	query := `
		UPDATE users
		SET notification_enabled = $2
		WHERE id = $1
		RETURNING id, email, name, username, photo_url, created_at, notification_enabled
	`
	var user models.User
	row := s.db.QueryRow(ctx, query, id, notificationEnabled)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	result, err := s.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *UserStorage) UpdatePhoto(ctx context.Context, id uuid.UUID, photoURL string) (*models.User, error) {
	query := `
		UPDATE users
		SET photo_url = $2
		WHERE id = $1
		RETURNING id, email, name, username, photo_url, created_at, notification_enabled
	`
	var user models.User
	row := s.db.QueryRow(ctx, query, id, photoURL)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) DeletePhoto(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		UPDATE users
		SET photo_url = NULL
		WHERE id = $1
		RETURNING id, email, name, username, photo_url, created_at, notification_enabled
	`
	var user models.User
	row := s.db.QueryRow(ctx, query, id)
	err := row.Scan(
		&user.ID, &user.Email, &user.Name, &user.Username,
		&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Загружаем провайдеры отдельно
	user.Providers, err = s.getUserProviders(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load providers: %w", err)
	}

	return &user, nil
}

func (s *UserStorage) RemoveProviderFromUser(ctx context.Context, userID uuid.UUID, provider string) error {
	query := `DELETE FROM user_providers WHERE user_id = $1 AND provider = $2`
	result, err := s.db.Exec(ctx, query, userID, provider)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *UserStorage) GetUserProviders(ctx context.Context, userID uuid.UUID) ([]models.OAuthProvider, error) {
	return s.getUserProviders(ctx, userID)
}

// SearchUsersRequest параметры поиска пользователей
type SearchUsersRequest struct {
	Query    string  // Поиск по name И username
	Name     *string // Только name (опционально)
	Username *string // Только username (опционально)
	Limit    int
	Offset   int
}

// SearchUsersResponse результат поиска пользователей
type SearchUsersResponse struct {
	Users  []models.User
	Total  int32
	Offset int
	Count  int
}

func (s *UserStorage) SearchUsers(ctx context.Context, req SearchUsersRequest) (*SearchUsersResponse, error) {
	// Построение WHERE clause
	whereClauses := []string{}
	args := []interface{}{}
	argNum := 1

	if req.Query != "" {
		whereClauses = append(whereClauses, "(name ILIKE $"+strconv.Itoa(argNum)+" OR username ILIKE $"+strconv.Itoa(argNum)+")")
		args = append(args, "%"+req.Query+"%")
		argNum++
	} else {
		if req.Name != nil && *req.Name != "" {
			whereClauses = append(whereClauses, "name ILIKE $"+strconv.Itoa(argNum))
			args = append(args, "%"+*req.Name+"%")
			argNum++
		}
		if req.Username != nil && *req.Username != "" {
			whereClauses = append(whereClauses, "username ILIKE $"+strconv.Itoa(argNum))
			args = append(args, "%"+*req.Username+"%")
			argNum++
		}
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Count query
	countQuery := `SELECT COUNT(*) FROM users ` + whereClause
	var total int32
	err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, err
	}

	// Select query
	query := `
		SELECT id, email, name, username, photo_url, created_at, notification_enabled
		FROM users
		` + whereClause + `
		ORDER BY username
		LIMIT $` + strconv.Itoa(argNum) + ` OFFSET $` + strconv.Itoa(argNum+1)

	args = append(args, req.Limit, req.Offset)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Email, &user.Name, &user.Username,
			&user.PhotoURL, &user.CreatedAt, &user.NotificationEnabled,
		)
		if err != nil {
			return nil, err
		}

		// Загружаем провайдеры для каждого пользователя
		user.Providers, err = s.getUserProviders(ctx, user.ID)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &SearchUsersResponse{
		Users:  users,
		Total:  total,
		Offset: req.Offset,
		Count:  len(users),
	}, nil
}

// CopyCardSetRequest запрос на копирование набора карточек
type CopyCardSetRequest struct {
	UserID    uuid.UUID
	SetID     uuid.UUID
	NewSetID  uuid.UUID
}

func (s *UserStorage) CopyCardSet(ctx context.Context, req CopyCardSetRequest) error {
	// Копируем набор карточек
	copySetQuery := `
		INSERT INTO card_sets (id, owner_id, name, description, is_public, created_at)
		SELECT $1, $2, name, description, false, NOW()
		FROM card_sets
		WHERE id = $3
	`
	_, err := s.db.Exec(ctx, copySetQuery, req.NewSetID, req.UserID, req.SetID)
	if err != nil {
		return fmt.Errorf("copy card set: %w", err)
	}

	// Копируем карточки
	copyCardsQuery := `
		INSERT INTO cards (id, set_id, front, back, image_url, audio_url, created_at)
		SELECT gen_random_uuid(), $1, front, back, image_url, audio_url, NOW()
		FROM cards
		WHERE set_id = $2
	`
	_, err = s.db.Exec(ctx, copyCardsQuery, req.NewSetID, req.SetID)
	if err != nil {
		return fmt.Errorf("copy cards: %w", err)
	}

	return nil
}

// SaveDeviceToken saves or updates a device token for push notifications
func (s *UserStorage) SaveDeviceToken(ctx context.Context, userID uuid.UUID, deviceType, token, appVersion string) error {
	query := `
		INSERT INTO device_tokens (user_id, device_type, token, app_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (user_id, device_type, token) DO UPDATE
		SET app_version = $4, updated_at = NOW()
	`
	_, err := s.db.Exec(ctx, query, userID, deviceType, token, appVersion)
	if err != nil {
		return fmt.Errorf("save device token: %w", err)
	}
	return nil
}

// GetDeviceTokens returns all device tokens for a user
func (s *UserStorage) GetDeviceTokens(ctx context.Context, userID uuid.UUID) ([]models.DeviceToken, error) {
	query := `
		SELECT id, user_id, device_type, token, app_version, created_at, updated_at
		FROM device_tokens
		WHERE user_id = $1
		ORDER BY updated_at DESC
	`
	rows, err := s.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []models.DeviceToken
	for rows.Next() {
		var token models.DeviceToken
		err := rows.Scan(
			&token.ID, &token.UserID, &token.DeviceType, &token.Token,
			&token.AppVersion, &token.CreatedAt, &token.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

// DeleteDeviceToken removes a device token
func (s *UserStorage) DeleteDeviceToken(ctx context.Context, userID uuid.UUID, token string) error {
	query := `DELETE FROM device_tokens WHERE user_id = $1 AND token = $2`
	_, err := s.db.Exec(ctx, query, userID, token)
	if err != nil {
		return fmt.Errorf("delete device token: %w", err)
	}
	return nil
}

// DeleteAllDeviceTokens removes all device tokens for a user (e.g., on logout)
func (s *UserStorage) DeleteAllDeviceTokens(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM device_tokens WHERE user_id = $1`
	_, err := s.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete all device tokens: %w", err)
	}
	return nil
}
