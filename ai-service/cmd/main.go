package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
)

func main() {
	cfg := config.LoadConfig("/app/config.yml")

	llmClient := createLLMClient(cfg.LLM)

	aiService := services.NewAIService(
		llmClient,
		cfg.CardService.URL,
		cfg.CardService.Timeout,
	)

	aiHandler := handlers.NewAIHandler(aiService)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	jwtConf := loadJWTConfig(cfg.JWT)
	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          jwtConf,
		DefaultHeader: "X-Internal-Token",
	})

	ai := r.Group("/v1.0", authMiddleware)
	{
		ai.POST("/generate-cards", aiHandler.GenerateCards)
		ai.POST("/generate-quiz", aiHandler.GenerateQuiz)
		ai.POST("/summarize", aiHandler.Summarize)
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

	log.Printf("Using LLM provider: %s, model: %s", cfg.Provider, cfg.Model)
	return services.NewOpenAIClient(cfg.APIKey, cfg.BaseURL, cfg.Model)
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
