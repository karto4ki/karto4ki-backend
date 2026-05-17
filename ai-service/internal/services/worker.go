package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/clients"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/kafka"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/storage"
)

type WorkerService struct {
	llmClient     LLMClient
	cardClient    *clients.CardServiceClient
	taskStorage   *storage.GenerationTaskStorage
	kafkaProducer *kafka.Producer
}

func NewWorkerService(
	llmClient LLMClient,
	cardClient *clients.CardServiceClient,
	taskStorage *storage.GenerationTaskStorage,
	kafkaProducer *kafka.Producer,
) *WorkerService {
	return &WorkerService{
		llmClient:     llmClient,
		cardClient:    cardClient,
		taskStorage:   taskStorage,
		kafkaProducer: kafkaProducer,
	}
}

func (w *WorkerService) ProcessTask(ctx context.Context, task *kafka.GenerationTaskMessage) error {
	log.Printf("Processing task %s for user %s", task.TaskID, task.UserID)

	// Publish event: task started
	_ = w.kafkaProducer.PublishEvent(ctx, &kafka.GenerationEventMessage{
		TaskID:    task.TaskID,
		UserID:    task.UserID,
		EventType: "task.processing",
		Status:    "processing",
		Timestamp: time.Now(),
	})

	// Update status to processing
	if err := w.taskStorage.UpdateProgress(ctx, task.TaskID, 0, models.TaskStatusProcessing); err != nil {
		return fmt.Errorf("update progress: %w", err)
	}

	// Generate cards from LLM
	cards, err := w.llmClient.GenerateCards(ctx, task.Text, task.CardCount, task.Difficulty, task.Language)
	if err != nil {
		_ = w.taskStorage.FailTask(ctx, task.TaskID, fmt.Sprintf("LLM generation failed: %v", err))
		_ = w.kafkaProducer.PublishEvent(ctx, &kafka.GenerationEventMessage{
			TaskID:    task.TaskID,
			UserID:    task.UserID,
			EventType: "task.failed",
			Status:    "failed",
			Error:     fmt.Sprintf("LLM generation failed: %v", err),
			Timestamp: time.Now(),
		})
		return fmt.Errorf("generate cards: %w", err)
	}

	// Remove duplicates
	cards = DeduplicateCards(cards)

	// Update progress after LLM generation
	if err := w.taskStorage.UpdateProgress(ctx, task.TaskID, len(cards), models.TaskStatusProcessing); err != nil {
		return fmt.Errorf("update progress: %w", err)
	}

	// Create card set
	var description *string
	if task.SetDescription != "" {
		description = &task.SetDescription
	}
	setID, err := w.createCardSet(ctx, task.UserID, task.SetName, description)
	if err != nil {
		_ = w.taskStorage.FailTask(ctx, task.TaskID, fmt.Sprintf("Failed to create card set: %v", err))
		_ = w.kafkaProducer.PublishEvent(ctx, &kafka.GenerationEventMessage{
			TaskID:    task.TaskID,
			UserID:    task.UserID,
			EventType: "task.failed",
			Status:    "failed",
			Error:     fmt.Sprintf("Failed to create card set: %v", err),
			Timestamp: time.Now(),
		})
		return fmt.Errorf("create card set: %w", err)
	}

	// Create individual cards with progress updates
	for i, card := range cards {
		if err := w.createCard(ctx, setID, card.Front, card.Back, nil, nil); err != nil {
			_ = w.deleteCardSet(ctx, setID, task.UserID)
			_ = w.taskStorage.FailTask(ctx, task.TaskID, fmt.Sprintf("Failed to create card %d: %v", i+1, err))
			_ = w.kafkaProducer.PublishEvent(ctx, &kafka.GenerationEventMessage{
				TaskID:    task.TaskID,
				UserID:    task.UserID,
				EventType: "task.failed",
				Status:    "failed",
				Error:     fmt.Sprintf("Failed to create card %d: %v", i+1, err),
				Timestamp: time.Now(),
			})
			return fmt.Errorf("create card %d: %w", i+1, err)
		}
		_ = w.taskStorage.UpdateProgress(ctx, task.TaskID, i+1, models.TaskStatusProcessing)
	}

	// Mark task as completed
	if err := w.taskStorage.CompleteTask(ctx, task.TaskID, setID); err != nil {
		_ = w.kafkaProducer.PublishEvent(ctx, &kafka.GenerationEventMessage{
			TaskID:    task.TaskID,
			UserID:    task.UserID,
			EventType: "task.failed",
			Status:    "failed",
			Error:     fmt.Sprintf("Failed to complete task: %v", err),
			Timestamp: time.Now(),
		})
		return fmt.Errorf("complete task: %w", err)
	}

	// Publish event: task completed
	_ = w.kafkaProducer.PublishEvent(ctx, &kafka.GenerationEventMessage{
		TaskID:    task.TaskID,
		UserID:    task.UserID,
		EventType: "task.completed",
		Status:    "completed",
		SetID:     setID,
		Timestamp: time.Now(),
	})

	log.Printf("Task %s completed successfully, set_id: %s", task.TaskID, setID)
	return nil
}

func (w *WorkerService) createCardSet(ctx context.Context, userID, name string, description *string) (string, error) {
	result, err := w.cardClient.CreateCardSet(ctx, userID, name, description, false)
	if err != nil {
		return "", err
	}
	return result.SetID, nil
}

func (w *WorkerService) createCard(ctx context.Context, setID, front, back string, imageURL, audioURL *string) error {
	_, err := w.cardClient.CreateCard(ctx, setID, front, back, imageURL, audioURL)
	return err
}

func (w *WorkerService) deleteCardSet(ctx context.Context, setID, userID string) error {
	_, err := w.cardClient.DeleteCardSet(ctx, setID, userID)
	return err
}
