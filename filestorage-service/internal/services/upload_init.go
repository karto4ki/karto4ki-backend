package services

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
)

type UploadInitRequest struct {
	FileName string `json:"file_name" binding:"required"`
	MimeType string `json:"mime_type" binding:"required"`
}

type UploadMetaStorer interface {
	Store(context.Context, *models.UploadMeta) error
}

type UploadInitService struct {
	metaStorer UploadMetaStorer
	client     *s3.Client
	bucket     string
}

func NewUploadInitService(metaStorer UploadMetaStorer, client *s3.Client, bucket string) *UploadInitService {
	return &UploadInitService{
		metaStorer: metaStorer,
		client:     client,
		bucket:     bucket,
	}
}

func (s *UploadInitService) Init(ctx context.Context, req *UploadInitRequest) (uuid.UUID, error) {
	fileID := uuid.New()

	// Создаем multipart upload в S3
	res, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(fileID.String()),
		ContentType: aws.String(req.MimeType),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("creating multipart upload: %w", err)
	}

	meta := &models.UploadMeta{
		PublicUploadID: uuid.New(),
		FileID:         fileID,
		Key:            fileID.String(),
		FileName:       req.FileName,
		MimeType:       req.MimeType,
		S3UploadID:     *res.UploadId,
		CreatedAt:      time.Now(),
	}

	if err := s.metaStorer.Store(ctx, meta); err != nil {
		return uuid.Nil, fmt.Errorf("storing upload meta: %w", err)
	}

	return meta.PublicUploadID, nil
}
