package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/karto4ki/karto4ki-backend/identity-service/internal/jwt"
	"github.com/redis/go-redis/v9"
)

const (
	prefix = "RevokedToken"
)

var (
	ErrRevokingToken        = errors.New("failed to revoke token")
	ErrCheckTokenRevocation = errors.New("failed to check token revocation")
)

type RevokeStorage struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRevokeStorage(clint *redis.Client, ttl time.Duration) *RevokeStorage {
	return &RevokeStorage{
		client: clint,
		ttl:    ttl,
	}
}

func (storage *RevokeStorage) Revoke(ctx context.Context, jwtToken jwt.Token) error {
	key := storage.generateKey(jwtToken, prefix)
	err := storage.client.Set(ctx, key, "revoked", storage.ttl).Err()
	if err != nil {
		return ErrRevokingToken
	}
	return nil
}

func (storage *RevokeStorage) IsRevoked(ctx context.Context, jwtToken jwt.Token) (bool, error) {
	key := storage.generateKey(jwtToken, prefix)
	exists, err := storage.client.Exists(ctx, key).Result()
	if err != nil {
		return false, ErrCheckTokenRevocation
	}
	return exists > 0, nil
}

func (storage *RevokeStorage) generateKey(jwtToken jwt.Token, prefix string) string {
	hash := sha256.Sum256([]byte(jwtToken))
	hashStr := hex.EncodeToString(hash[:])

	return fmt.Sprintf("%s:%s", prefix, hashStr)
}
