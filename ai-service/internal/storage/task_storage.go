package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/models"
	"github.com/redis/go-redis/v9"
)

type GenerationTaskStorage struct {
	client *redis.Client
	ttl    time.Duration
}

func NewGenerationTaskStorage(client *redis.Client, ttlHours int) *GenerationTaskStorage {
	return &GenerationTaskStorage{
		client: client,
		ttl:    time.Duration(ttlHours) * time.Hour,
	}
}

func (s *GenerationTaskStorage) key(taskID string) string {
	return fmt.Sprintf("generation_task:%s", taskID)
}

func (s *GenerationTaskStorage) CreateTask(ctx context.Context, task *models.GenerationTask) error {
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}

	key := s.key(task.TaskID)
	return s.client.Set(ctx, key, data, s.ttl).Err()
}

func (s *GenerationTaskStorage) GetTask(ctx context.Context, taskID string) (*models.GenerationTask, error) {
	key := s.key(taskID)
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("get task: %w", err)
	}

	var task models.GenerationTask
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("unmarshal task: %w", err)
	}

	return &task, nil
}

func (s *GenerationTaskStorage) UpdateTask(ctx context.Context, task *models.GenerationTask) error {
	task.UpdatedAt = time.Now()
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}

	key := s.key(task.TaskID)
	return s.client.Set(ctx, key, data, s.ttl).Err()
}

func (s *GenerationTaskStorage) UpdateProgress(ctx context.Context, taskID string, generatedCards int, status models.TaskStatus) error {
	task, err := s.GetTask(ctx, taskID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("task not found: %s", taskID)
	}

	task.GeneratedCards = generatedCards
	task.Status = status
	if task.TotalCards > 0 {
		task.Progress = (generatedCards * 100) / task.TotalCards
	}

	return s.UpdateTask(ctx, task)
}

func (s *GenerationTaskStorage) CompleteTask(ctx context.Context, taskID, setID string) error {
	task, err := s.GetTask(ctx, taskID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("task not found: %s", taskID)
	}

	now := time.Now()
	task.Status = models.TaskStatusCompleted
	task.SetID = setID
	task.Progress = 100
	task.GeneratedCards = task.TotalCards
	task.CompletedAt = &now

	return s.UpdateTask(ctx, task)
}

func (s *GenerationTaskStorage) FailTask(ctx context.Context, taskID, errMsg string) error {
	task, err := s.GetTask(ctx, taskID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("task not found: %s", taskID)
	}

	now := time.Now()
	task.Status = models.TaskStatusFailed
	task.Error = errMsg
	task.Progress = 0
	task.CompletedAt = &now

	return s.UpdateTask(ctx, task)
}

func (s *GenerationTaskStorage) DeleteTask(ctx context.Context, taskID string) error {
	key := s.key(taskID)
	return s.client.Del(ctx, key).Err()
}
