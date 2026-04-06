package storage

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var (
	ErrAuthKeyNotFound   = errors.New("auth key was not found")
	ErrFailGetAuthKey    = errors.New("getting data failed")
	ErrUnmarshalDataFail = errors.New("unmarshalling meta failed")
	ErrParseUUIDFail     = errors.New("uuid parsing failed")
)

type AuthData struct {
	AuthKey     uuid.UUID
	LastRequest time.Time
	UserId      uuid.UUID
	Email       string
	Name        string
	Username    string
	Code        string
	Verified    bool
}

type AuthStorage struct {
	client *redis.Client
	ttl    time.Duration
}

func NewAuthStorage(client *redis.Client, ttl time.Duration) *AuthStorage {
	return &AuthStorage{
		client: client,
		ttl:    ttl,
	}
}

func (s *AuthStorage) Remove(ctx context.Context, key uuid.UUID) error {
	keyStr := "Auth: " + key.String()
	res := s.client.Del(ctx, keyStr)
	if err := res.Err(); err != nil {
		return err
	}
	return nil
}

func (s *AuthStorage) FindKey(ctx context.Context, authKey uuid.UUID) (*AuthData, error) {
	key := "Auth: " + authKey.String()
	res := s.client.Get(ctx, key)
	if err := res.Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAuthKeyNotFound
		}
		return nil, ErrFailGetAuthKey
	}

	meta := new(AuthData)
	if err := json.Unmarshal([]byte(res.Val()), meta); err != nil {
		return nil, ErrUnmarshalDataFail
	}
	return meta, nil
}

func (s AuthStorage) FindKeyByEmail(ctx context.Context, email string) (*AuthData, error) {
	emailKey := "EmailKey: " + email
	resp := s.client.Get(ctx, emailKey)
	log.Printf("findkey start")
	if err := resp.Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			log.Printf("redis nil")
			return nil, ErrAuthKeyNotFound
		}
		log.Printf("FindKeyByEmail: %s", err)
		return nil, ErrFailGetAuthKey
	}

	key, err := uuid.Parse(resp.Val())
	if err != nil {
		log.Printf("after parse: %s", err)
		return nil, ErrParseUUIDFail
	}
	return s.FindKey(ctx, key)
}

func (s AuthStorage) Store(ctx context.Context, data *AuthData) error {
	metaJson, err := json.Marshal(data)
	if err != nil {
		return ErrUnmarshalDataFail
	}

	key := data.AuthKey.String()
	metaKey := "Auth: " + key
	phoneKey := "EmailKey: " + data.Email

	status := s.client.Set(ctx, metaKey, metaJson, s.ttl)
	if err := status.Err(); err != nil {
		return err
	}

	status = s.client.Set(ctx, phoneKey, key, s.ttl)
	if err := status.Err(); err != nil {
		return err
	}

	return nil
}
