package services

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
)

var ErrUploadNotFound = errors.New("upload not found")

type UploadPartRequest struct {
	PartNumber int       `json:"part_number" binding:"required"`
	UploadID   uuid.UUID `json:"upload_id" binding:"required"`
	Part       io.Reader
}

type UploadPartResponse struct {
	ETag string `json:"e_tag"`
}

type UploadMetaGetter interface {
	Get(context.Context, uuid.UUID) (*models.UploadMeta, bool, error)
}

type UploadPartService struct {
	metaGetter UploadMetaGetter
	client     *s3.Client
	bucket     string
}

func NewUploadPartService(metaGetter UploadMetaGetter, client *s3.Client, bucket string) *UploadPartService {
	return &UploadPartService{
		metaGetter: metaGetter,
		client:     client,
		bucket:     bucket,
	}
}

func (s *UploadPartService) UploadPart(ctx context.Context, req *UploadPartRequest) (*UploadPartResponse, error) {
	meta, ok, err := s.metaGetter.Get(ctx, req.UploadID)
	if err != nil {
		return nil, fmt.Errorf("getting upload meta: %w", err)
	}
	if !ok {
		return nil, ErrUploadNotFound
	}

	// Загружаем часть в S3
	res, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(s.bucket),
		Key:        aws.String(meta.Key),
		PartNumber: aws.Int32(int32(req.PartNumber)),
		UploadId:   aws.String(meta.S3UploadID),
		Body:       req.Part,
	})
	if err != nil {
		return nil, fmt.Errorf("uploading part: %w", err)
	}

	return &UploadPartResponse{
		ETag: *res.ETag,
	}, nil
}
