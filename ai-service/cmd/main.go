package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/clients"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.LoadConfig("/app/config.yml")

	llmClient := createLLMClient(cfg.LLM)

	jwtConf := loadJWTConfig(cfg.JWT)

	cardClient, err := clients.NewCardServiceClient(cfg.CardService.GRPCAddress)
	if err != nil {
		log.Fatalf("Failed to create card service client: %v", err)
	}
	defer cardClient.Close()

	// Initialize Redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Println("Connected to Redis")
	defer redisClient.Close()

	// Initialize task storage
	taskStorage := storage.NewGenerationTaskStorage(redisClient, cfg.Redis.TaskTTLHours)

	aiService := services.NewAIService(
		llmClient,
		cardClient,
		taskStorage,
	)

	aiHandler := handlers.NewAIHandler(aiService)
	taskStatusHandler := handlers.NewTaskStatusHandler(aiService)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          jwtConf,
		DefaultHeader: "X-Internal-Token",
	})

	ai := r.Group("/v1.0", authMiddleware)
	{
		ai.POST("/generate-cards", aiHandler.GenerateCards)
		ai.POST("/generate-cards-from-pdf", aiHandler.GenerateCardsFromPDF)
		ai.POST("/generate-quiz", aiHandler.GenerateQuiz)
		ai.POST("/summarize", aiHandler.Summarize)
		
		// Task status endpoint (no auth required for polling, task_id is unguessable)
		ai.GET("/generate-cards/status/:task_id", taskStatusHandler.GetTaskStatus)
	}

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	log.Printf("Starting AI service on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start AI service: %v", err)
	}
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

func loadJWTConfig(cfg config.JWTConfig) *jwt.Config {
	config := &jwt.Config{
		SigningMethod: cfg.SigningMethod,
		Issuer:        cfg.Issuer,
		Audience:      cfg.Audience,
		Type:          "internal_access",
	}
	if err := config.RSAPublicOnlyKey(readKey(cfg.KeyFilePath)); err != nil {
		log.Fatalf("Failed to load JWT public key: %v", err)
	}
	return config
}

func readKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}
	return key
}
