package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/clients"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/kafka"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/storage"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.LoadConfig("/app/config.yml")

	log.Println("Starting AI Worker...")

	// Initialize Redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	cancel()
	log.Println("Connected to Redis")
	defer redisClient.Close()

	// Initialize task storage
	taskStorage := storage.NewGenerationTaskStorage(redisClient, cfg.Redis.TaskTTLHours)

	// Initialize card service client
	cardClient, err := clients.NewCardServiceClient(cfg.CardService.GRPCAddress)
	if err != nil {
		log.Fatalf("Failed to create card service client: %v", err)
	}
	defer cardClient.Close()

	// Initialize LLM client
	llmClient := createLLMClient(cfg.LLM)

	// Create worker service
	workerService := services.NewWorkerService(llmClient, cardClient, taskStorage)

	// Create Kafka consumer
	kafkaConsumer := kafka.NewConsumer(cfg.Kafka, func(ctx context.Context, task *kafka.GenerationTaskMessage) error {
		return workerService.ProcessTask(ctx, task)
	})

	// Start consumer with concurrency
	concurrency := cfg.Kafka.Consumer.Concurrency
	if envConcurrency := os.Getenv("WORKER_CONCURRENCY"); envConcurrency != "" {
		if _, err := fmt.Sscanf(envConcurrency, "%d", &concurrency); err != nil {
			log.Printf("Invalid WORKER_CONCURRENCY, using default: %d", concurrency)
		}
	}

	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	kafkaConsumer.Start(consumerCtx, concurrency)

	log.Printf("AI Worker started with %d workers", concurrency)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	consumerCancel()
	kafkaConsumer.Stop()

	log.Println("AI Worker stopped")
}

func createLLMClient(cfg config.LLMConfig) services.LLMClient {
	if os.Getenv("LLM_MOCK") == "true" {
		log.Println("Using mock LLM client")
		return services.NewMockLLMClient()
	}

	if cfg.APIKey == "" {
		log.Println("Warning: LLM API key not set, using mock client")
		return services.NewMockLLMClient()
	}

	log.Printf("Using LLM provider: %s, model: %s, base_url: %s", cfg.Provider, cfg.Model, cfg.BaseURL)
	return services.NewOpenAIClient(cfg.APIKey, cfg.BaseURL, cfg.Model, cfg.Provider)
}
