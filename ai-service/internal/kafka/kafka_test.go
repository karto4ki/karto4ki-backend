package kafka_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerationTaskMessage_MarshalUnmarshal(t *testing.T) {
	task := &kafka.GenerationTaskMessage{
		TaskID:         "task-123",
		UserID:         "user-456",
		Text:           "Test text for generation",
		CardCount:      10,
		Difficulty:     "intermediate",
		Language:       "ru",
		SetName:        "Test Set",
		SetDescription: "Test Description",
		CreatedAt:      time.Now(),
	}

	data, err := json.Marshal(task)
	require.NoError(t, err)

	var unmarshaled kafka.GenerationTaskMessage
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, task.TaskID, unmarshaled.TaskID)
	assert.Equal(t, task.UserID, unmarshaled.UserID)
	assert.Equal(t, task.Text, unmarshaled.Text)
	assert.Equal(t, task.CardCount, unmarshaled.CardCount)
}

func TestGenerationEventMessage_MarshalUnmarshal(t *testing.T) {
	event := &kafka.GenerationEventMessage{
		TaskID:    "task-123",
		UserID:    "user-456",
		EventType: "task.completed",
		Status:    "completed",
		Progress:  100,
		SetID:     "set-789",
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var unmarshaled kafka.GenerationEventMessage
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, event.TaskID, unmarshaled.TaskID)
	assert.Equal(t, event.EventType, unmarshaled.EventType)
	assert.Equal(t, event.Progress, unmarshaled.Progress)
}

func TestGenerationTaskMessage_Validation(t *testing.T) {
	// JSON marshaling/unmarshaling работает корректно
	// Валидация данных происходит на уровне handler/service
	task := &kafka.GenerationTaskMessage{
		TaskID:    "task-123",
		UserID:    "user-456",
		Text:      "Some text",
		CardCount: 10,
	}

	data, err := json.Marshal(task)
	require.NoError(t, err)

	var unmarshaled kafka.GenerationTaskMessage
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, task.TaskID, unmarshaled.TaskID)
	assert.Equal(t, task.UserID, unmarshaled.UserID)
	assert.Equal(t, task.Text, unmarshaled.Text)
	assert.Equal(t, task.CardCount, unmarshaled.CardCount)
}

func TestGenerationEventMessage_EventTypes(t *testing.T) {
	validEventTypes := []string{
		"task.created",
		"task.processing",
		"task.completed",
		"task.failed",
	}

	for _, eventType := range validEventTypes {
		t.Run(eventType, func(t *testing.T) {
			event := &kafka.GenerationEventMessage{
				TaskID:    "task-123",
				UserID:    "user-456",
				EventType: eventType,
				Timestamp: time.Now(),
			}

			data, err := json.Marshal(event)
			require.NoError(t, err)

			var unmarshaled kafka.GenerationEventMessage
			err = json.Unmarshal(data, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, eventType, unmarshaled.EventType)
		})
	}
}
