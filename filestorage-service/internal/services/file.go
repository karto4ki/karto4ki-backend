package services

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
)

type FileService struct {
	fileMetaStorer FileMetaStorer
	client         *s3.Client
	bucket         string
}

func NewFileService(fileMetaStorer FileMetaStorer, client *s3.Client, bucket string) *FileService {
	return &FileService{
		fileMetaStorer: fileMetaStorer,
		client:         client,
		bucket:         bucket,
	}
}

// GetFileMeta получает метаданные файла из Redis
func (s *FileService) GetFileMeta(ctx context.Context, fileID uuid.UUID) (*models.FileMeta, bool, error) {
	return s.fileMetaStorer.Get(ctx, fileID)
}

// DeleteFile удаляет файл из S3 и метаданные из Redis
func (s *FileService) DeleteFile(ctx context.Context, fileID uuid.UUID) error {
	// Удаляем файл из S3
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fileID.String()),
	})
	if err != nil {
		return fmt.Errorf("deleting from S3: %w", err)
	}

	// Удаляем метаданные из Redis
	if err := s.fileMetaStorer.Delete(ctx, fileID); err != nil {
		return fmt.Errorf("deleting file meta: %w", err)
	}

	return nil
}
