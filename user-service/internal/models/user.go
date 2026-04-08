package models

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID                  uuid.UUID `db:"id"`
	Name                string    `db:"name"`
	Username            string    `db:"username"`
	Email               *string   `db:"email"`
	PhotoURL            *string   `db:"photo_url"`
	CreatedAt           time.Time `db:"created_at"`
	NotificationEnabled bool      `db:"notification_enabled"`
	Provider            *string   `db:"provider"`
	ProviderId          *string   `db:"provider_id"`
}

type Achievement struct {
	UserId uuid.UUID `db:"user_id"`
	Sets   int64     `db:"sets"`
	Streak int64     `db:"streak"`
}
