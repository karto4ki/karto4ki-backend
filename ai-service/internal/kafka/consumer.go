package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/config"
	"github.com/segmentio/kafka-go"
)

type TaskHandler func(ctx context.Context, task *GenerationTaskMessage) error

type Consumer struct {
	reader  *kafka.Reader
	cfg     config.KafkaConfig
	handler TaskHandler
	wg      sync.WaitGroup
}

func NewConsumer(cfg config.KafkaConfig, handler TaskHandler) *Consumer {
	return &Consumer{
		reader: kafka.NewReader(kafka.ReaderConfig{
			Brokers:  cfg.Brokers,
			Topic:    cfg.Topics.GenerationTasks,
			GroupID:  cfg.ConsumerGroup,
			MinBytes: 10,
			MaxBytes: 10e6,
			MaxWait:  100 * time.Millisecond,
		}),
		cfg:     cfg,
		handler: handler,
	}
}

func (c *Consumer) Start(ctx context.Context, concurrency int) {
	log.Printf("Starting Kafka consumer with %d workers", concurrency)

	for i := 0; i < concurrency; i++ {
		c.wg.Add(1)
		go c.worker(ctx, i)
	}
}

func (c *Consumer) worker(ctx context.Context, workerID int) {
	defer c.wg.Done()
	log.Printf("Worker %d started", workerID)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Worker %d stopping", workerID)
			return
		default:
			msg, err := c.reader.FetchMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("Worker %d fetch error: %v", workerID, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if err := c.processMessage(ctx, msg, workerID); err != nil {
				log.Printf("Worker %d process error: %v", workerID, err)
			}
		}
	}
}

func (c *Consumer) processMessage(ctx context.Context, msg kafka.Message, workerID int) error {
	var task GenerationTaskMessage
	if err := json.Unmarshal(msg.Value, &task); err != nil {
		log.Printf("Worker %d failed to unmarshal message: %v", workerID, err)
		return nil
	}

	log.Printf("Worker %d processing task %s for user %s", workerID, task.TaskID, task.UserID)

	retries := 0
	for retries < c.cfg.Consumer.MaxRetries {
		if err := c.handler(ctx, &task); err != nil {
			retries++
			log.Printf("Worker %d retry %d/%d for task %s: %v", workerID, retries, c.cfg.Consumer.MaxRetries, task.TaskID, err)
			time.Sleep(time.Duration(c.cfg.Consumer.RetryDelayMs) * time.Millisecond)
			continue
		}

		if err := c.reader.CommitMessages(ctx, msg); err != nil {
			log.Printf("Worker %d failed to commit message: %v", workerID, err)
		}
		log.Printf("Worker %d completed task %s", workerID, task.TaskID)
		return nil
	}

	log.Printf("Worker %d failed task %s after %d retries", workerID, task.TaskID, retries)
	return fmt.Errorf("max retries exceeded")
}

func (c *Consumer) Stop() {
	log.Println("Stopping Kafka consumer...")
	if err := c.reader.Close(); err != nil {
		log.Printf("Failed to close reader: %v", err)
	}
	c.wg.Wait()
	log.Println("Kafka consumer stopped")
}
