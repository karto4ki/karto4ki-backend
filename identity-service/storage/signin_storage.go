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
)

type SignInData struct {
	SignInKey uuid.UUID
	UserId    uuid.UUID
	Name      string
	Username  string
	Code      string
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
