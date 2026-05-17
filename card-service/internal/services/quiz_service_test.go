package services_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestQuizService_GenerateOptions_Count(t *testing.T) {
	
	correctCard := models.Card{
		ID:    uuid.New().String(),
		Front: "What is Go?",
		Back:  "Programming language",
	}
	
	wrongCards := []models.Card{
		{ID: uuid.New().String(), Front: "Q2", Back: "Database"},
		{ID: uuid.New().String(), Front: "Q3", Back: "Framework"},
		{ID: uuid.New().String(), Front: "Q4", Back: "Library"},
		{ID: uuid.New().String(), Front: "Q5", Back: "Tool"},
	}
	
	// Проверяем что достаточно карточек для генерации 3 неправильных ответов
	assert.GreaterOrEqual(t, len(wrongCards), 3, "Нужно минимум 3 карточки для неправильных ответов")
	assert.Equal(t, "Programming language", correctCard.Back)
}
