package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/karto4ki/karto4ki-backend/identity-service/services"
	"github.com/redis/go-redis/v9"
)

const (
	prefixLock = "idempotency:lock:"
	prefixMeta = "idempotency:meta"
	prefixData = "idempotency:data"
)

type RedisIdempotencyStorage struct {
	client        *redis.Client
	storageConfig StorageConfig
}

type StorageConfig struct {
	MetaTTL time.Duration
	DataTTL time.Duration
}

func NewRedisIdempotencyStorage(client *redis.Client, config StorageConfig) *RedisIdempotencyStorage {
	return &RedisIdempotencyStorage{
		client:        client,
		storageConfig: config,
	}
}

type cachedResponseMeta struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	DataKey    string      `json:"data_key"`
	CreatedAt  time.Time   `json:"created_at"`
}

func (s *RedisIdempotencyStorage) AcquireLock(ctx context.Context, key string, ttl time.Duration) (string, error) {
	lockKey := prefixLock + key
	lockTokenLength := 32
	bytes := make([]byte, lockTokenLength/2+1)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)[:lockTokenLength]
	success, err := s.client.SetNX(ctx, lockKey, token, ttl).Result()
	if err != nil {
		return "", fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !success {
		return "", fmt.Errorf("lock already acquired")
	}

	return token, nil
}

func (s *RedisIdempotencyStorage) ReleaseLock(ctx context.Context, key, token string) error {
	lockKey := prefixLock + key
	script := redis.NewScript(`
		local current = redis.call("GET", KEYS[1])
		if current == ARGV[1] then return redis.call("DEL", KEYS[1])
		end
		return 0
	`)

	_, err := script.Run(ctx, s.client, []string{lockKey}, token).Result()
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	return nil
}

func (s *RedisIdempotencyStorage) Get(ctx context.Context, key string) (*services.CapturedResponse, bool, error) {
	metaKey := prefixMeta + key

	metaJSON, err := s.client.Get(ctx, metaKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get metadata: %w", err)
	}

	var meta cachedResponseMeta
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		s.client.Del(ctx, metaKey)
		return nil, false, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	data, err := s.client.Get(ctx, meta.DataKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			s.client.Del(ctx, metaKey)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get data: %w", err)
	}

	response := &services.CapturedResponse{
		StatusCode: meta.StatusCode,
		Headers:    meta.Headers,
		Body:       data,
	}

	return response, true, nil
}

func (s *RedisIdempotencyStorage) Store(ctx context.Context, key string, resp *services.CapturedResponse) error {
	lockTokenLength := 16
	bytes := make([]byte, lockTokenLength/2+1)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)[:lockTokenLength]

	dataKey := prefixData + token

	if err := s.client.Set(ctx, dataKey, resp.Body, s.storageConfig.DataTTL).Err(); err != nil {
		return fmt.Errorf("failed to store data: %w", err)
	}

	meta := cachedResponseMeta{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		DataKey:    dataKey,
		CreatedAt:  time.Now(),
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		s.client.Del(ctx, dataKey)
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metaKey := prefixMeta + key
	if err := s.client.Set(ctx, metaKey, metaJSON, s.storageConfig.MetaTTL).Err(); err != nil {
		s.client.Del(ctx, dataKey)
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	return nil
}
