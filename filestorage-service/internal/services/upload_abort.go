package services

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

type UploadAbortService struct {
	uploadStorage UploadMetaGetRemover
	client        *s3.Client
	bucket        string
}

func NewUploadAbortService(uploadStorage UploadMetaGetRemover, client *s3.Client, bucket string) *UploadAbortService {
	return &UploadAbortService{
		uploadStorage: uploadStorage,
		client:        client,
		bucket:        bucket,
	}
}

func (s *UploadAbortService) Abort(ctx context.Context, uploadID uuid.UUID) error {
	upload, ok, err := s.uploadStorage.Get(ctx, uploadID)
	if err != nil {
		return fmt.Errorf("getting upload meta: %w", err)
	}
	if !ok {
		return ErrUploadNotFound
	}

	// Прерываем multipart upload в S3
	_, err = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(upload.Key),
		UploadId: aws.String(upload.S3UploadID),
	})
	if err != nil {
		return fmt.Errorf("aborting multipart upload: %w", err)
	}

	// Удаляем метаданные загрузки
	if err := s.uploadStorage.Remove(ctx, uploadID); err != nil {
		return fmt.Errorf("removing upload meta: %w", err)
	}

	return nil
}
