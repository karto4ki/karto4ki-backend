package services

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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

type SendCodeRepository interface {
	FindKeyByEmail(ctx context.Context, email string) (*storage.AuthData, error)
	Store(ctx context.Context, data *storage.AuthData) error
}

type SendCodeService struct {
	ttl         *time.Duration
	emailSender email.EmailSender
	repository  SendCodeRepository
	userService userservice.UserServiceClient
}

func NewSendCodeService(ttl *time.Duration, repository SendCodeRepository, email email.EmailSender, userservice userservice.UserServiceClient) *SendCodeService {
	return &SendCodeService{
		ttl:         ttl,
		emailSender: email,
		repository:  repository,
		userService: userservice,
	}
}

func (s *SendCodeService) SignInSendCode(ctx context.Context, email string) (uuid.UUID, bool, error) {
	data, err := s.repository.FindKeyByEmail(ctx, email)
	if err != nil && !errors.Is(err, storage.ErrAuthKeyNotFound) {
		log.Printf("SignInSendCode: %s", err)
		return uuid.Nil, false, ErrFindSignInMetaFail
	}
	log.Printf("not in err")
	if data != nil && data.LastRequest.Add(*s.ttl).Compare(time.Now().UTC()) > 0 {
		isExist := data.UserId != uuid.Nil
		return uuid.Nil, isExist, ErrSendCodeFreqExceeded
	}

	var userID uuid.UUID
	var username, name string
	var isExist bool

	userResp, err := s.userService.GetUserByEmail(ctx, &userservice.GetUserByEmailRequest{Email: email})
	if err != nil {
		log.Printf("get user by email fail: %s", err)
		return uuid.Nil, false, ErrGrpcFindMeta
	}
	switch userResp.Status {
	case userservice.GetUserResponseStatus_SUCCESS:
		isExist = true
		if userResp.UserId != nil {
			userID = uuid.MustParse(userResp.UserId.GetValue())
		}
		if userResp.Username != nil {
			username = *userResp.Username
		}
		if userResp.Name != nil {
			name = *userResp.Name
		}
	case userservice.GetUserResponseStatus_NOT_FOUND:
		isExist = false
	default:
		return uuid.Nil, false, ErrUnexpectedStatus
	}

	meta := storage.AuthData{
		AuthKey:     uuid.New(),
		LastRequest: time.Now().UTC(),
		Email:       email,
		UserId:      userID,
		Username:    username,
		Name:        name,
		Code:        genCode(),
	}

	if err := s.repository.Store(ctx, &meta); err != nil {
		return uuid.Nil, isExist, err
	}

	message := "Do not tell this code to anybody. Your code for karto4ki signing in is " + meta.Code
	if err := s.emailSender.SendEmail(ctx, email, message); err != nil {
		return uuid.Nil, isExist, ErrSendEmailFail
	}

	return meta.AuthKey, isExist, nil
}

func genCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random code")
	}
	n := 1e5 + binary.BigEndian.Uint32(b)%9e5
	return fmt.Sprintf("%06d", n)
}

func (s *SendCodeService) fetchUser(ctx context.Context, email string) (*userservice.GetUserResponse, error) {
	user, err := s.userService.GetUserByEmail(ctx, &userservice.GetUserByEmailRequest{
		Email: email,
	})

	if err != nil {
		return nil, err
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
