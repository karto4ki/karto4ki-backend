package services

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
)

var (
	ErrSignUpCodeSendFreqExceeded = errors.New("signup code send frequency exceeded")
	ErrWrongSignUpCode            = errors.New("wrong signup code")
	ErrUserAlreadyExists          = errors.New("user already exists")
	ErrCreateUserFailed           = errors.New("failed to create user")
	ErrEmailNotVerified           = errors.New("email was not verified")
)

type SignUpRepository interface {
	FindKey(ctx context.Context, key uuid.UUID) (*storage.AuthData, error)
	Remove(ctx context.Context, key uuid.UUID) error
}

type SignUpService struct {
	repo        SignUpRepository
	userService userservice.UserServiceClient
	accessConf  *jwt.Config
	refreshConf *jwt.Config
}

func NewSignUpService(
	repo SignUpRepository,
	userService userservice.UserServiceClient,
	accessConf, refreshConf *jwt.Config,
) *SignUpService {
	return &SignUpService{
		repo:        repo,
		userService: userService,
		accessConf:  accessConf,
		refreshConf: refreshConf,
	}
}

func (s *SignUpService) SignUp(ctx context.Context, signUpKey uuid.UUID, name, username string) (jwt.Pair, error) {
	if name == "" || username == "" {
		return jwt.Pair{}, ErrMissingRequiredFields
	}
	data, err := s.repo.FindKey(ctx, signUpKey)
	if err != nil {
		if errors.Is(err, storage.ErrAuthKeyNotFound) {
			return jwt.Pair{}, ErrAuthKeyNotFound
		}
		return jwt.Pair{}, err
	}

	if data.UserId != uuid.Nil {
		return jwt.Pair{}, ErrUserAlreadyExists
	}

	if !data.Verified {
		return jwt.Pair{}, ErrEmailNotVerified
	}

	createResp, err := s.userService.CreateUserWithEmail(ctx, &userservice.CreateUserWithEmailRequest{
		Email:    data.Email,
		Name:     name,
		Username: username,
	})
	if err != nil {
		return jwt.Pair{}, ErrCreateUserFailed
	}
	if createResp.Status != userservice.CreateUserStatus_CREATED {
		if createResp.Status == userservice.CreateUserStatus_ALREADY_EXISTS {
			return jwt.Pair{}, ErrUserAlreadyExists
		}
		return jwt.Pair{}, ErrCreateUserFailed
	}

	userId, err := uuid.Parse(createResp.UserId.Value)
	if err != nil {
		return jwt.Pair{}, ErrCreateUserFailed
	}

	claims := jwt.Claims{
		"sub":      userId.String(),
		"name":     name,
		"username": username,
	}
	var pair jwt.Pair
	if pair.Access, err = jwt.Generate(s.accessConf, claims); err != nil {
		return jwt.Pair{}, ErrAccessGeneration
	}
	if pair.Refresh, err = jwt.Generate(s.refreshConf, claims); err != nil {
		return jwt.Pair{}, ErrRefreshGeneration
	}

	_ = s.repo.Remove(ctx, signUpKey)
	return pair, nil
}

func generateCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random code")
	}
	n := 100000 + binary.BigEndian.Uint32(b)%900000
	return fmt.Sprintf("%06d", n)
}
