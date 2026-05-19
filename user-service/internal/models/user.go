package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                  uuid.UUID `db:"id"`
	Name                string    `db:"name"`
	Username            string    `db:"username"`
	Email               *string   `db:"email"`
	PhotoURL            *string   `db:"photo_url"`
	CreatedAt           time.Time `db:"created_at"`
	NotificationEnabled bool      `db:"notification_enabled"`
	LastActivityAt      time.Time `db:"last_activity_at"`
	Providers           []OAuthProvider `db:"-"` // Загружается отдельно
}

type OAuthProvider struct {
	ID         uuid.UUID `db:"id"`
	UserID     uuid.UUID `db:"user_id"`
	Provider   string    `db:"provider"`   // 'apple', 'google', etc.
	ProviderID string    `db:"provider_id"` // ID от провайдера
	CreatedAt  time.Time `db:"created_at"`
}

type DeviceToken struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	DeviceType string   `db:"device_type"` // 'ios' или 'android'
	Token     string    `db:"token"`
	AppVersion string  `db:"app_version"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type Achievement struct {
	UserId uuid.UUID `db:"user_id"`
	Sets   int64     `db:"sets"`
	Streak int64     `db:"streak"`
}
