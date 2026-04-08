package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/karto4ki/karto4ki-backend/shared/postgres"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/models"
)

type AchievementStorage struct {
	db postgres.SQLer
}

func NewAchievementStorage(db postgres.SQLer) *AchievementStorage {
	return &AchievementStorage{db: db}
}

func (s *AchievementStorage) Create(ctx context.Context, userID uuid.UUID) error {
	query := `INSERT INTO achievements (user_id, sets, streak) VALUES ($1, 0, 0)`
	_, err := s.db.Exec(ctx, query, userID)
	return err
}

func (s *AchievementStorage) UpdateSets(ctx context.Context, userID uuid.UUID, sets int32) error {
	query := `UPDATE achievements SET sets = sets + $1 WHERE user_id = $2`
	res, err := s.db.Exec(ctx, query, sets, userID)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *AchievementStorage) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.Achievement, error) {
	var ach models.Achievement
	query := `SELECT user_id, sets, streak FROM achievements WHERE user_id = $1`
	row := s.db.QueryRow(ctx, query, userID)
	err := row.Scan(&ach.UserId, &ach.Sets, &ach.Streak)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &ach, nil
}
