package services

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
)

type UploadFileService struct {
	fileMetaStorer FileMetaStorer
	client         *s3.Client
	bucket         string
	urlPrefix      string
}

func NewUploadFileService(fileMetaStorer FileMetaStorer, client *s3.Client, bucket, urlPrefix string) *UploadFileService {
	return &UploadFileService{
		fileMetaStorer: fileMetaStorer,
		client:         client,
		bucket:         bucket,
		urlPrefix:      urlPrefix,
	}
}

func (s *UploadFileService) UploadFile(ctx context.Context, data []byte, fileName, mimeType, fileType, ownerID string) (*models.UploadResponse, error) {
	fileID := uuid.New()

	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(fileID.String()),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(mimeType),
		Metadata: map[string]string{
			"owner_id":  ownerID,
			"file_type": fileType,
			"file_name": fileName,
			"mime_type": mimeType,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("uploading to S3: %w", err)
	}

	fileMeta := &models.FileMeta{
		FileID:    fileID,
		OwnerID:   ownerID,
		FileName:  fileName,
		MimeType:  mimeType,
		FileType:  fileType,
		FileSize:  int64(len(data)),
		FileURL:   s.urlPrefix + "/api/storage/v1.0/files/" + fileID.String() + "/raw",
		CreatedAt: time.Now(),
	}

	// Сохраняем метаданные в Redis
	if err := s.fileMetaStorer.Store(ctx, fileMeta); err != nil {
		// Откатываем загрузку в S3 при ошибке
		s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(fileID.String()),
		})
		return nil, fmt.Errorf("storing file meta: %w", err)
	}

	return &models.UploadResponse{
		FileID:    fileID.String(),
		FileURL:   fileMeta.FileURL,
		FileType:  fileMeta.FileType,
		FileSize:  fileMeta.FileSize,
		MimeType:  fileMeta.MimeType,
		CreatedAt: fileMeta.CreatedAt,
	}, nil
}
