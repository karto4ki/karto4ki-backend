package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"

	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/postgres"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/config"
	pb "github.com/karto4ki/karto4ki-backend/user-service/internal/grpc"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
)

var cfg = config.LoadConfig("/app/config.yml")

func main() {
	jwtConf := config.LoadJWTConfig(cfg)

	dbURL := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.DB.Host, cfg.DB.Port, cfg.DB.User, cfg.DB.Password, cfg.DB.DBName, cfg.DB.SSLMode)
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	if err := db.Ping(); err != nil {
		log.Fatalf("database unreachable: %v", err)
	}
	log.Println("database connected")

	sqlDB := postgres.NewDB(db)

	userStorage := storage.NewUserStorage(sqlDB)
	achievementStorage := storage.NewAchievementStorage(sqlDB)

	userService := services.NewUserService(userStorage)
	achievementService := services.NewAchievementService(achievementStorage)

	grpcServer := handlers.NewGrpcServer(userService, achievementService)
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatalf("failed to listen on gRPC port %d: %v", cfg.GRPCPort, err)
	}
	gs := grpc.NewServer()
	pb.RegisterUserServiceServer(gs, grpcServer)

	go func() {
		log.Printf("gRPC server listening on :%d", cfg.GRPCPort)
		if err := gs.Serve(grpcLis); err != nil {
			log.Fatalf("gRPC server error: %v", err)
		}
	}()

	gin.SetMode(gin.DebugMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	userHandler := handlers.NewUserHandler(userService)
	fileStorageURL := os.Getenv("FILE_STORAGE_URL")
	if fileStorageURL == "" {
		fileStorageURL = "http://filestorage-service:8081"
	}
	profileHandler := handlers.NewProfileHandler(userService, fileStorageURL)
	achievementHandler := handlers.NewAchievementHandler(achievementService)

	r.GET("/v1.0/username/:username", userHandler.CheckUsername)
	r.GET("/are-you-a-real-teapot", func(c *gin.Context) {
		c.JSON(http.StatusTeapot, gin.H{"message": "I'm a teapot"})
	})

	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          jwtConf,
		DefaultHeader: "X-Internal-Token",
	})

	auth := r.Group("/v1.0")
	auth.Use(authMiddleware)
	{
		auth.GET("/user/:username", userHandler.GetPublicProfile)
		auth.GET("/users", userHandler.SearchUsers)

		auth.GET("/me", profileHandler.GetMyProfile)
		auth.PUT("/me", profileHandler.UpdateMyProfile)
		auth.DELETE("/me", profileHandler.DeleteMyProfile)

		auth.PUT("/me/profile-photo", profileHandler.UpdateProfilePhoto)
		auth.DELETE("/me/profile-photo", profileHandler.DeleteProfilePhoto)

		auth.GET("/me/achievements", achievementHandler.GetMyAchievements)
	}

	httpAddr := fmt.Sprintf(":%d", cfg.HTTPPort)
	httpSrv := &http.Server{
		Addr:    httpAddr,
		Handler: r,
	}

	go func() {
		log.Printf("HTTP server listening on %s", httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Fatal("HTTP server forced shutdown:", err)
	}
	gs.GracefulStop()
	log.Println("servers stopped")
}
