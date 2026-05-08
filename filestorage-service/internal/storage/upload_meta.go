package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
	"github.com/redis/go-redis/v9"
)

// UploadMetaStorage хранит метаданные многокомпонентной загрузки в Redis
type UploadMetaStorage struct {
	client  *redis.Client
	ttl     time.Duration
	keyPrefix string
}

func NewUploadMetaStorage(client *redis.Client, ttl time.Duration) *UploadMetaStorage {
	return &UploadMetaStorage{
		client:    client,
		ttl:       ttl,
		keyPrefix: "upload:meta:",
	}
}

func (s *UploadMetaStorage) key(uploadID uuid.UUID) string {
	return fmt.Sprintf("%s%s", s.keyPrefix, uploadID.String())
}

// Store сохраняет метаданные загрузки
func (s *UploadMetaStorage) Store(ctx context.Context, meta *models.UploadMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal upload meta: %w", err)
	}

	return s.client.Set(ctx, s.key(meta.PublicUploadID), data, s.ttl).Err()
}

// Get получает метаданные загрузки
func (s *UploadMetaStorage) Get(ctx context.Context, uploadID uuid.UUID) (*models.UploadMeta, bool, error) {
	data, err := s.client.Get(ctx, s.key(uploadID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get upload meta: %w", err)
	}

	var meta models.UploadMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, false, fmt.Errorf("unmarshal upload meta: %w", err)
	}

	return &meta, true, nil
}

// Remove удаляет метаданные загрузки
func (s *UploadMetaStorage) Remove(ctx context.Context, uploadID uuid.UUID) error {
	return s.client.Del(ctx, s.key(uploadID)).Err()
}

// FileMetaStorage хранит метаданные файлов в Redis
type FileMetaStorage struct {
	client    *redis.Client
	keyPrefix string
}

func NewFileMetaStorage(client *redis.Client) *FileMetaStorage {
	return &FileMetaStorage{
		client:    client,
		keyPrefix: "file:meta:",
	}
}

func (s *FileMetaStorage) key(fileID uuid.UUID) string {
	return fmt.Sprintf("%s%s", s.keyPrefix, fileID.String())
}

// Store сохраняет метаданные файла
func (s *FileMetaStorage) Store(ctx context.Context, meta *models.FileMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal file meta: %w", err)
	}

	return s.client.Set(ctx, s.key(meta.FileID), data, 0).Err()
}

// Get получает метаданные файла
func (s *FileMetaStorage) Get(ctx context.Context, fileID uuid.UUID) (*models.FileMeta, bool, error) {
	data, err := s.client.Get(ctx, s.key(fileID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get file meta: %w", err)
	}

	var meta models.FileMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, false, fmt.Errorf("unmarshal file meta: %w", err)
	}

	return &meta, true, nil
}

// Delete удаляет метаданные файла
func (s *FileMetaStorage) Delete(ctx context.Context, fileID uuid.UUID) error {
	return s.client.Del(ctx, s.key(fileID)).Err()
}
