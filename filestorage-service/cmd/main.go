package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.LoadConfig("/app/config.yml")

	// Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Проверка подключения к Redis
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Printf("Connected to Redis at %s", cfg.Redis.Addr)

	// S3 client
	s3Client := createS3Client(cfg)

	// Storages
	uploadMetaStorage := storage.NewUploadMetaStorage(redisClient, cfg.Idempotency.DataExp)
	fileMetaStorage := storage.NewFileMetaStorage(redisClient)

	// JWT auth middleware
	jwtConf := loadJWTConfig(cfg.Jwt)
	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          jwtConf,
		DefaultHeader: "X-Internal-Token",
	})

	// Services
	uploadInitSvc := services.NewUploadInitService(uploadMetaStorage, s3Client, cfg.S3.Bucket)
	uploadPartSvc := services.NewUploadPartService(uploadMetaStorage, s3Client, cfg.S3.Bucket)
	uploadCompleteSvc := services.NewUploadCompleteService(fileMetaStorage, uploadMetaStorage, s3Client, cfg.S3.Bucket, cfg.S3.URLPrefix)
	uploadAbortSvc := services.NewUploadAbortService(uploadMetaStorage, s3Client, cfg.S3.Bucket)

	// Handlers
	uploadInitHandler := handlers.UploadInit(uploadInitSvc)
	uploadPartHandler := handlers.UploadPart(&handlers.MultipartUploadConfig{
		MaxPartSize: cfg.MultipartUpload.MaxPartSize,
	}, uploadPartSvc)
	uploadCompleteHandler := handlers.UploadComplete(uploadCompleteSvc)
	uploadAbortHandler := handlers.UploadAbort(uploadAbortSvc)

	// Router
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, restapi.ErrorResponse{
			ErrorType:    restapi.ErrTypeFileNotFound,
			ErrorMessage: "Endpoint not found",
		})
	})

	// Multipart upload endpoints
	multipart := r.Group("/v1.0/upload/multipart", authMiddleware)
	{
		multipart.POST("/init", uploadInitHandler)
		multipart.PUT("/part", uploadPartHandler)
		multipart.POST("/complete", uploadCompleteHandler)
		multipart.PUT("/abort", uploadAbortHandler)
	}

	addr := fmt.Sprintf(":%d", cfg.GRPCService.Port)
	log.Printf("Starting filestorage-service on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func createS3Client(cfg *config.Config) *s3.Client {
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               "http://" + cfg.S3.Endpoint,
				SigningRegion:     cfg.AWS.Region,
				HostnameImmutable: true,
			}, nil
		},
	)

	s3Client := s3.NewFromConfig(aws.Config{
		Region: cfg.AWS.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.AWS.AccessKeyID,
			cfg.AWS.SecretAccessKey,
			"",
		),
		EndpointResolverWithOptions: customResolver,
	}, func(o *s3.Options) {
		o.UsePathStyle = true // MinIO требует path-style addressing
	})

	return s3Client
}

func loadJWTConfig(cfg config.JWTConfig) *jwt.Config {
	jwtConf := &jwt.Config{
		SigningMethod: cfg.SigningMethod,
		Lifetime:      cfg.Lifetime,
		Issuer:        cfg.Issuer,
		Audience:      cfg.Audience,
		Type:          "internal_access",
	}
	if err := jwtConf.RSAPublicOnlyKey(readKey(cfg.KeyFilePath)); err != nil {
		log.Fatalf("Failed to load JWT public key: %v", err)
	}
	return jwtConf
}

func readKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}
	return key
}
