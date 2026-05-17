package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/config"
	"github.com/segmentio/kafka-go"
)

type GenerationTaskMessage struct {
	TaskID         string    `json:"task_id"`
	UserID         string    `json:"user_id"`
	Text           string    `json:"text"`
	CardCount      int       `json:"card_count"`
	Difficulty     string    `json:"difficulty"`
	Language       string    `json:"language"`
	SetName        string    `json:"set_name"`
	SetDescription string    `json:"set_description"`
	CreatedAt      time.Time `json:"created_at"`
}

type GenerationEventMessage struct {
	TaskID     string    `json:"task_id"`
	UserID     string    `json:"user_id"`
	EventType  string    `json:"event_type"`
	Status     string    `json:"status,omitempty"`
	Progress   int       `json:"progress,omitempty"`
	SetID      string    `json:"set_id,omitempty"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

type Producer struct {
	writer *kafka.Writer
	cfg    config.KafkaConfig
}

func NewProducer(cfg config.KafkaConfig) *Producer {
	return &Producer{
		writer: &kafka.Writer{
			Addr:         kafka.TCP(cfg.Brokers...),
			Topic:        cfg.Topics.GenerationTasks,
			Balancer:     &kafka.LeastBytes{},
			BatchSize:    10,
			BatchTimeout: 10 * time.Millisecond,
			RequiredAcks: kafka.RequiredAcks(cfg.Producer.RequiredAcks),
		},
		cfg: cfg,
	}
}

func (p *Producer) Close() error {
	return p.writer.Close()
}

func (p *Producer) PublishTask(ctx context.Context, task *GenerationTaskMessage) error {
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(task.TaskID),
		Value: data,
		Time:  time.Now(),
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("publish task: %w", err)
	}

	return nil
}

func (p *Producer) PublishEvent(ctx context.Context, event *GenerationEventMessage) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(event.TaskID),
		Value: data,
		Time:  time.Now(),
	}

	eventWriter := &kafka.Writer{
		Addr:         kafka.TCP(p.cfg.Brokers...),
		Topic:        p.cfg.Topics.GenerationEvents,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequiredAcks(p.cfg.Producer.RequiredAcks),
	}
	defer eventWriter.Close()

	if err := eventWriter.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("publish event: %w", err)
	}

	return nil
}
