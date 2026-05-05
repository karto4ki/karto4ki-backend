package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func main() {
	cfg := config.LoadConfig("/app/config.yml")

	jwtConf := config.LoadJWTConfig(cfg)
	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          jwtConf,
		DefaultHeader: "X-Internal-Token",
	})

	var s3Client *minio.Client
	var err error
	if cfg.S3.Enabled {
		s3Client, err = initS3Client(cfg.S3)
		if err != nil {
			log.Fatalf("Failed to initialize S3 client: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := createBucketIfNotExists(ctx, s3Client, cfg.S3.Bucket); err != nil {
			log.Fatalf("Failed to create S3 bucket: %v", err)
		}
		log.Printf("S3 client initialized, bucket: %s", cfg.S3.Bucket)
	}

	fileService := services.NewFileService(services.Config{
		StoragePath:    cfg.StoragePath,
		MaxFileSize:    cfg.MaxFileSize,
		AllowedTypes:   cfg.AllowedTypes,
		ThumbnailSizes: cfg.ThumbnailSizes,
		S3Client:       s3Client,
		S3Bucket:       cfg.S3.Bucket,
		S3Enabled:      cfg.S3.Enabled,
	})

	fileHandler := handlers.NewFileHandler(fileService)

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.POST("/v1.0/upload", authMiddleware, fileHandler.UploadFile)

	files := r.Group("/v1.0/files", authMiddleware)
	{
		files.GET("/:fileId", fileHandler.GetFileInfo)
		files.DELETE("/:fileId", fileHandler.DeleteFile)
		files.GET("/:fileId/raw", fileHandler.GetRawFile)
	}

	images := r.Group("/v1.0/images", authMiddleware)
	{
		images.GET("/:imageId/resize", fileHandler.ResizeImage)
		images.GET("/:imageId/thumbnail", fileHandler.GetThumbnail)
	}

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	log.Printf("Starting filestorage-service service on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func initS3Client(cfg config.S3Config) (*minio.Client, error) {
	return minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
}

func createBucketIfNotExists(ctx context.Context, client *minio.Client, bucket string) error {
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !exists {
		return client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	}
	return nil
}
