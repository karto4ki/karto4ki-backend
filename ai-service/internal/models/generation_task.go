package models

import "time"

type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusProcessing TaskStatus = "processing"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
)

type GenerationTask struct {
	TaskID         string     `json:"task_id"`
	UserID         string     `json:"user_id"`
	Status         TaskStatus `json:"status"`
	Progress       int        `json:"progress"`
	TotalCards     int        `json:"total_cards"`
	GeneratedCards int        `json:"generated_cards"`
	SetID          string     `json:"set_id,omitempty"`
	SetName        string     `json:"set_name"`
	Error          string     `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}
