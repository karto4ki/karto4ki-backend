package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
)

type AchievementRepository interface {
	Create(ctx context.Context, userID uuid.UUID) error
	UpdateSets(ctx context.Context, userID uuid.UUID, sets int32) error
}

type AchievementService struct {
	repo AchievementRepository
}

func NewAchievementService(repo AchievementRepository) *AchievementService {
	return &AchievementService{repo: repo}
}

func (s *AchievementService) Create(ctx context.Context, userID uuid.UUID) error {
	return s.repo.Create(ctx, userID)
}

func (s *AchievementService) UpdateSets(ctx context.Context, userID uuid.UUID, sets int32) error {
	err := s.repo.UpdateSets(ctx, userID, sets)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}
