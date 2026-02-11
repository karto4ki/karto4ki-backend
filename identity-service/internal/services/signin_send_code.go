package services

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/email"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
)

var (
	ErrFindSignInMetaFail   = errors.New("failed to find sign in meta")
	ErrSendCodeFreqExceeded = errors.New("send code operation freauency exceeded")
	ErrUserNotFound         = errors.New("user not found")
	ErrGrpcFindMeta         = errors.New("failed to find sign in meta")
	ErrUnknownGrpcError     = errors.New("unknown grpc getting user by email error")
	ErrUnexpectedStatus     = errors.New("unexpected user service status code")
	ErrSendEmailFail        = errors.New("send email message error")
)

type SignInSendCodeRepository interface {
	FindKeyByEmail(ctx context.Context, email string) (*storage.SignInData, error)
	Store(ctx context.Context, data *storage.SignInData) error
}

type SignInSendCodeService struct {
	ttl         *time.Duration
	emailSender email.EmailSender
	repository  SignInSendCodeRepository
	userService userservice.UserServiceClient
}

func NewSignInSendCodeService(ttl *time.Duration, repository SignInSendCodeRepository, email email.EmailSender, userservice userservice.UserServiceClient) *SignInSendCodeService {
	return &SignInSendCodeService{
		ttl:         ttl,
		emailSender: email,
		repository:  repository,
		userService: userservice,
	}
}

func (s *SignInSendCodeService) SignInSendCode(ctx context.Context, email string) (uuid.UUID, error) {
	data, err := s.repository.FindKeyByEmail(ctx, email)
	if err != nil {
		return uuid.Nil, ErrFindSignInMetaFail
	}
	if data != nil && data.LastRequest.Add(*s.ttl).Compare(time.Now().UTC()) > 0 {
		return uuid.Nil, ErrSendCodeFreqExceeded
	}

	var user *userservice.GetUserResponse
	if user, err = s.fetchUser(ctx, email); err != nil {
		return uuid.Nil, err
	}
	meta := storage.SignInData{
		SignInKey:   uuid.New(),
		LastRequest: time.Now().UTC(),
		Email:       email,
		UserId:      uuid.MustParse(user.UserId.GetValue()),
		Username:    *user.Username,
		Name:        *user.Name,
		Code:        genCode(),
	}
	message := "Do not tell this code to anybody. Your code for karto4ki signing in is " + meta.Code
	if err := s.emailSender.SendEmail(ctx, email, message); err != nil {
		return uuid.Nil, ErrSendEmailFail
	}
	if err := s.repository.Store(ctx, &meta); err != nil {
		return uuid.Nil, err
	}

	return meta.SignInKey, err
}

func genCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random code")
	}
	n := 1e5 + binary.BigEndian.Uint32(b)%9e5
	return fmt.Sprintf("%06d", n)
}

func (s *SignInSendCodeService) fetchUser(ctx context.Context, email string) (*userservice.GetUserResponse, error) {
	user, err := s.userService.GetUserByEmail(ctx, &userservice.GetUserByEmailRequest{
		Email: email,
	})

	if err != nil {
		return nil, ErrGrpcFindMeta
	}
	if user.Status != userservice.GetUserResponseStatus_SUCCESS {
		if user.Status == userservice.GetUserResponseStatus_FAILED {
			return nil, ErrUnknownGrpcError
		}
		if user.Status == userservice.GetUserResponseStatus_NOT_FOUND {
			return nil, ErrUserNotFound
		}
		return nil, ErrUnexpectedStatus
	}

	return user, nil
}
