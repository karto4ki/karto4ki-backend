package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/userclient"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/karto4ki/karto4ki-backend/shared/postgres"
	_ "github.com/lib/pq"
	"gopkg.in/yaml.v3"
)

func main() {
	cfg := loadConfig()

	db := connectDB(cfg.DB)

	cardSetStorage := storage.NewCardSetStorage(db)
	cardStorage := storage.NewCardStorage(db)
	sessionStorage := storage.NewStudySessionStorage(db)
	statsStorage := storage.NewStatisticsStorage(db)

	userClient := userclient.NewClient("http://user-service:8080")

	cardSetService := services.NewCardSetService(cardSetStorage, cardStorage, userClient)
	cardService := services.NewCardService(cardSetStorage, cardStorage)
	learningService := services.NewLearningService(cardSetStorage, cardStorage, sessionStorage, statsStorage)

	cardSetHandler := handlers.NewCardSetHandler(cardSetService)
	cardHandler := handlers.NewCardHandler(cardService)
	learningHandler := handlers.NewLearningHandler(learningService)

	jwtConf := loadJWTConfig(cfg.JWT)
	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf: jwtConf,
	})

	r := gin.Default()

	r.POST("/api/card/v1.0/sets", authMiddleware, cardSetHandler.CreateCardSet)

	sets := r.Group("/api/card/v1.0/sets", authMiddleware)
	{
		sets.GET("", cardSetHandler.GetCardSets)
		sets.GET("/:setId", cardSetHandler.GetCardSet)
		sets.PUT("/:setId", cardSetHandler.UpdateCardSet)
		sets.DELETE("/:setId", cardSetHandler.DeleteCardSet)

		sets.GET("/:setId/cards", cardHandler.GetCards)
		sets.POST("/:setId/cards", cardHandler.CreateCard)

		sets.POST("/:setId/study", learningHandler.StartStudySession)
		sets.GET("/:setId/stats", learningHandler.GetSetStatistics)
	}

	cards := r.Group("/api/card/v1.0/cards", authMiddleware)
	{
		cards.GET("/:cardId", cardHandler.GetCard)
		cards.PUT("/:cardId", cardHandler.UpdateCard)
		cards.DELETE("/:cardId", cardHandler.DeleteCard)
	}

	study := r.Group("/api/card/v1.0/study", authMiddleware)
	{
		study.POST("/:sessionId/answer", learningHandler.SubmitAnswer)
	}

	search := r.Group("/api/card/v1.0/search", authMiddleware)
	{
		search.GET("", cardSetHandler.SearchPublicSets)
		search.POST("/:setId/clone", cardSetHandler.CloneSet)
	}

	me := r.Group("/api/card/v1.0/me", authMiddleware)
	{
		me.GET("/stats", learningHandler.GetUserStatistics)
	}

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	log.Printf("Starting card-service on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func loadConfig() config.Config {
	cfg := config.Config{
		HTTPPort: 8082,
		DB: config.DBConfig{
			Host:     "card-db",
			Port:     5432,
			User:     "card",
			Password: "password",
			Name:     "carddb",
			SSLMode:  "disable",
		},
		JWT: config.JWTConfig{
			SigningMethod: "RS256",
			Issuer:        "karto4ki-backend",
			Audience:      []string{"card_service"},
			KeyFilePath:   "/app/keys/rsa.pub",
		},
	}

	data, err := os.ReadFile("config.yml")
	if err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Printf("Failed to parse config: %v, using defaults", err)
		}
	}

	return cfg
}

func loadJWTConfig(cfg config.JWTConfig) *jwt.Config {
	config := &jwt.Config{
		SigningMethod: cfg.SigningMethod,
		Issuer:        cfg.Issuer,
		Audience:      cfg.Audience,
		Type:          "access",
	}
	if err := config.RSAPublicOnlyKey(readKey(cfg.KeyFilePath)); err != nil {
		log.Fatal(err)
	}
	return config
}

func readKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func connectDB(cfg config.DBConfig) *postgres.DB {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)

	db, err := sql.Open("pq", dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Connected to database")
	return postgres.NewDB(db)
}
