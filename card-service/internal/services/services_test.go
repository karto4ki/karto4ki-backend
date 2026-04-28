package services_test

import (
	"testing"
	"time"

	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestCalculateSpacedRepetition_CorrectAnswer(t *testing.T) {
	tests := []struct {
		name           string
		currentStatus  models.CardStatus
		errorCount     int32
		expectedStatus models.CardStatus
		expectedDays   int
		expectedStreak int32
		expectedErrors int32
	}{
		{"New to Learning", models.StatusNew, 0, models.StatusLearning, 1, 1, 0},
		{"Learning to Reviewing", models.StatusLearning, 0, models.StatusReviewing, 3, 2, 0},
		{"Reviewing stays Reviewing", models.StatusReviewing, 0, models.StatusReviewing, 7, 3, 0},
		{"Mastered stays Mastered", models.StatusMastered, 0, models.StatusMastered, 30, 5, 0},
		{"Reviewing with errors", models.StatusReviewing, 3, models.StatusReviewing, 7, 3, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, nextReview, streak, errorCount := services.CalculateSpacedRepetition(tt.currentStatus, tt.errorCount, true)

			assert.Equal(t, tt.expectedStatus, status)
			assert.Equal(t, tt.expectedStreak, streak)
			assert.Equal(t, tt.expectedErrors, errorCount)

			expectedDate := time.Now().AddDate(0, 0, tt.expectedDays)
			assert.InDelta(t, expectedDate.Unix(), nextReview.Unix(), 60)
		})
	}
}

func TestCalculateSpacedRepetition_IncorrectAnswer(t *testing.T) {
	tests := []struct {
		name           string
		currentStatus  models.CardStatus
		errorCount     int32
		expectedErrors int32
	}{
		{"New with errors", models.StatusNew, 0, 1},
		{"Learning with errors", models.StatusLearning, 1, 2},
		{"Reviewing with errors", models.StatusReviewing, 2, 3},
		{"Mastered with errors", models.StatusMastered, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, nextReview, streak, errorCount := services.CalculateSpacedRepetition(tt.currentStatus, tt.errorCount, false)

			assert.Equal(t, models.StatusLearning, status)
			assert.Equal(t, int32(0), streak)
			assert.Equal(t, tt.expectedErrors, errorCount)

			expectedDate := time.Now().AddDate(0, 0, 1)
			assert.InDelta(t, expectedDate.Unix(), nextReview.Unix(), 60)
		})
	}
}
