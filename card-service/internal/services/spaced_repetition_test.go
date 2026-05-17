package services_test

import (
	"testing"
	"time"

	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestCalculateSpacedRepetition_LearnMode(t *testing.T) {
	tests := []struct {
		name           string
		currentStatus  models.CardStatus
		errorCount     int32
		rating         models.CardRating
		expectedStatus models.CardStatus
		expectedDays   int
		expectedStreak int32
		expectedErrors int32
	}{
		// Помню - прогресс вперёд
		{"New→Learning", models.StatusNew, 0, models.RatingRemember, models.StatusLearning, 1, 1, 0},
		{"Learning→Reviewing", models.StatusLearning, 0, models.RatingRemember, models.StatusReviewing, 3, 2, 0},
		{"Reviewing→Reviewing(7d)", models.StatusReviewing, 0, models.RatingRemember, models.StatusReviewing, 7, 3, 0},
		{"Mastered→Mastered(30d)", models.StatusMastered, 0, models.RatingRemember, models.StatusMastered, 30, 5, 0},
		
		// Не помню - сброс на learning
		{"New→Learning(forgot)", models.StatusNew, 0, models.RatingForgot, models.StatusLearning, 1, 0, 1},
		{"Learning→Learning(forgot)", models.StatusLearning, 0, models.RatingForgot, models.StatusLearning, 1, 0, 1},
		{"Reviewing→Learning(forgot)", models.StatusReviewing, 2, models.RatingForgot, models.StatusLearning, 1, 0, 3},
		{"Mastered→Learning(forgot)", models.StatusMastered, 0, models.RatingForgot, models.StatusLearning, 1, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, nextReview, streak, errorCount := services.CalculateSpacedRepetition(
				tt.currentStatus,
				tt.errorCount,
				tt.rating,
			)

			assert.Equal(t, tt.expectedStatus, status)
			assert.Equal(t, tt.expectedStreak, streak)
			assert.Equal(t, tt.expectedErrors, errorCount)

			expectedDate := time.Now().AddDate(0, 0, tt.expectedDays)
			assert.InDelta(t, expectedDate.Unix(), nextReview.Unix(), 60)
		})
	}
}
