package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"gopkg.in/yaml.v3"
)

type Config struct {
	HTTPPort       int            `yaml:"http_port"`
	StoragePath    string         `yaml:"storage_path"`
	MaxFileSize    int64          `yaml:"max_file_size"`
	AllowedTypes   []string       `yaml:"allowed_types"`
	ThumbnailSizes map[string]int `yaml:"thumbnail_sizes"`
	JWT            JWTConfig      `yaml:"jwt"`
	S3             S3Config       `yaml:"s3"`
}

type S3Config struct {
	Enabled   bool   `yaml:"enabled"`
	Endpoint  string `yaml:"endpoint"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	UseSSL    bool   `yaml:"use_ssl"`
	Region    string `yaml:"region"`
}

type JWTConfig struct {
	SigningMethod string        `yaml:"signing_method"`
	Lifetime      time.Duration `yaml:"lifetime"`
	Issuer        string        `yaml:"issuer"`
	Audience      []string      `yaml:"audience"`
	KeyFilePath   string        `yaml:"key_file_path"`
}

func main() {
	config := loadConfig()

	jwtConf := loadJWTConfig(config.JWT)
	authMiddleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          jwtConf,
		DefaultHeader: "X-Internal-Token",
	})

	var s3Client *minio.Client
	var err error
	if config.S3.Enabled {
		s3Client, err = initS3Client(config.S3)
		if err != nil {
			log.Fatalf("Failed to initialize S3 client: %v", err)
		}
		if err := createBucketIfNotExists(s3Client, config.S3.Bucket); err != nil {
			log.Fatalf("Failed to create S3 bucket: %v", err)
		}
		log.Printf("S3 client initialized, bucket: %s", config.S3.Bucket)
	}

	fileService := services.NewFileService(services.Config{
		StoragePath:    config.StoragePath,
		MaxFileSize:    config.MaxFileSize,
		AllowedTypes:   config.AllowedTypes,
		ThumbnailSizes: config.ThumbnailSizes,
		S3Client:       s3Client,
		S3Bucket:       config.S3.Bucket,
		S3Enabled:      config.S3.Enabled,
	})

	fileHandler := handlers.NewFileHandler(fileService)

	r := gin.Default()

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

	addr := fmt.Sprintf(":%d", config.HTTPPort)
	log.Printf("Starting filestorage-service service on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func initS3Client(cfg S3Config) (*minio.Client, error) {
	return minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
}

func createBucketIfNotExists(client *minio.Client, bucket string) error {
	exists, err := client.BucketExists(context.Background(), bucket)
	if err != nil {
		return err
	}
	if !exists {
		return client.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{})
	}
	return nil
}

func loadJWTConfig(cfg JWTConfig) *jwt.Config {
	config := &jwt.Config{
		SigningMethod: cfg.SigningMethod,
		Lifetime:      cfg.Lifetime,
		Issuer:        cfg.Issuer,
		Audience:      cfg.Audience,
		Type:          "internal_access",
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

func loadConfig() Config {
	config := Config{
		HTTPPort:    8081,
		StoragePath: "./uploads",
		MaxFileSize: 10 * 1024 * 1024,
		AllowedTypes: []string{
			"image/jpeg",
			"image/png",
			"image/gif",
			"image/webp",
			"image/svg+xml",
		},
		ThumbnailSizes: map[string]int{
			"small":  100,
			"medium": 300,
			"large":  600,
		},
		JWT: JWTConfig{
			SigningMethod: "RS256",
			Issuer:        "identity_service",
			Audience:      []string{"identity_service"},
			KeyFilePath:   "/app/keys/rsa.pub",
		},
	}

	data, err := os.ReadFile("config.yml")
	if err == nil {
		if err := yaml.Unmarshal(data, &config); err != nil {
			log.Printf("Failed to parse config: %v, using defaults", err)
		}
	}

	return config
}
