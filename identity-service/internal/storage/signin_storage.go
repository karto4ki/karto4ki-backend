package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var (
	ErrSignInKeyNotFound = errors.New("sign in key was not found")
	ErrFailGetSignInKey  = errors.New("getting data failed")
	ErrUnmarshalDataFail = errors.New("unmarshalling meta failed")
	ErrParseUUIDFail     = errors.New("uuid parsing failed")
)

type SignInData struct {
	SignInKey   uuid.UUID
	LastRequest time.Time
	UserId      uuid.UUID
	Email       string
	Name        string
	Username    string
	Code        string
}

type SignInStorage struct {
	client *redis.Client
	ttl    time.Duration
}

func NewSignInStorage(client *redis.Client, ttl time.Duration) *SignInStorage {
	return &SignInStorage{
		client: client,
		ttl:    ttl,
	}
}

func (s *SignInStorage) Remove(ctx context.Context, signInKey uuid.UUID) error {
	key := "Sign In: " + signInKey.String()
	res := s.client.Del(ctx, key)
	if err := res.Err(); err != nil {
		return err
	}
	return nil
}

func (s *SignInStorage) FindKey(ctx context.Context, signInKey uuid.UUID) (*SignInData, error) {
	key := "Sign In: " + signInKey.String()
	res := s.client.Get(ctx, key)
	if err := res.Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSignInKeyNotFound
		}
		return nil, ErrFailGetSignInKey
	}

	meta := new(SignInData)
	if err := json.Unmarshal([]byte(res.Val()), meta); err != nil {
		return nil, ErrUnmarshalDataFail
	}
	return meta, nil
}

func (s SignInStorage) FindKeyByEmail(ctx context.Context, email string) (*SignInData, error) {
	emailKey := "EmailKey: " + email
	resp := s.client.Get(ctx, emailKey)
	if err := resp.Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSignInKeyNotFound
		}
		return nil, ErrFailGetSignInKey
	}

	key, err := uuid.Parse(resp.Val())
	if err != nil {
		return nil, ErrParseUUIDFail
	}
	return s.FindKey(ctx, key)
}

func (s SignInStorage) Store(ctx context.Context, data *SignInData) error {
	metaJson, err := json.Marshal(data)
	if err != nil {
		return ErrUnmarshalDataFail
	}

	key := data.SignInKey.String()
	metaKey := "Sign In: " + key
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
