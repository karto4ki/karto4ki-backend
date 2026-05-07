package services

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
)

type UploadCompleteRequest struct {
	UploadID uuid.UUID    `json:"upload_id" binding:"required"`
	Parts    []UploadPart `json:"parts" binding:"required"`
}

type UploadPart struct {
	PartNumber int    `json:"part_number" binding:"required"`
	ETag       string `json:"e_tag" binding:"required"`
}

type FileMetaStorer interface {
	Store(context.Context, *models.FileMeta) error
}

type UploadMetaGetRemover interface {
	Get(context.Context, uuid.UUID) (*models.UploadMeta, bool, error)
	Remove(context.Context, uuid.UUID) error
}

type UploadCompleteService struct {
	fileMetaStorage FileMetaStorer
	uploadStorage   UploadMetaGetRemover
	client          *s3.Client
	bucket          string
	urlPrefix       string
}

func NewUploadCompleteService(
	fileMetaStorage FileMetaStorer,
	uploadStorage UploadMetaGetRemover,
	client *s3.Client,
	bucket string,
	urlPrefix string,
) *UploadCompleteService {
	return &UploadCompleteService{
		fileMetaStorage: fileMetaStorage,
		uploadStorage:   uploadStorage,
		client:          client,
		bucket:          bucket,
		urlPrefix:       urlPrefix,
	}
}

func (s *UploadCompleteService) Complete(ctx context.Context, req *UploadCompleteRequest) (*models.FileMeta, error) {
	upload, ok, err := s.uploadStorage.Get(ctx, req.UploadID)
	if err != nil {
		return nil, fmt.Errorf("getting upload meta: %w", err)
	}
	if !ok {
		return nil, ErrUploadNotFound
	}

	// Завершаем multipart upload в S3
	_, err = s.completeS3Upload(ctx, upload, req)
	if err != nil {
		return nil, fmt.Errorf("completing multipart upload: %w", err)
	}

	// Удаляем метаданные загрузки
	if err := s.uploadStorage.Remove(ctx, upload.PublicUploadID); err != nil {
		return nil, fmt.Errorf("removing upload meta: %w", err)
	}

	// Получаем размер файла из S3
	head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(upload.Key),
	})
	if err != nil {
		return nil, fmt.Errorf("getting object head: %w", err)
	}

	file := &models.FileMeta{
		FileID:    upload.FileID,
		FileName:  upload.FileName,
		MimeType:  upload.MimeType,
		FileSize:  *head.ContentLength,
		FileURL:   s.buildFileURL(upload.FileID),
		CreatedAt: time.Now(),
	}

	// Сохраняем метаданные файла
	if err := s.fileMetaStorage.Store(ctx, file); err != nil {
		return nil, fmt.Errorf("storing file meta: %w", err)
	}

	return file, nil
}

func (s *UploadCompleteService) completeS3Upload(ctx context.Context, upload *models.UploadMeta, req *UploadCompleteRequest) (*s3.CompleteMultipartUploadOutput, error) {
	parts := make([]types.CompletedPart, 0, len(req.Parts))
	for _, p := range req.Parts {
		parts = append(parts, types.CompletedPart{
			ETag:       aws.String(p.ETag),
			PartNumber: aws.Int32(int32(p.PartNumber)),
		})
	}

	return s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(upload.Key),
		UploadId: aws.String(upload.S3UploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	})
}

func (s *UploadCompleteService) buildFileURL(fileID uuid.UUID) string {
	return fmt.Sprintf("%s%s", s.urlPrefix, fileID.String())
}
