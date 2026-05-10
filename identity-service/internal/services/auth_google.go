package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/oauth"
	pb "github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
)

var (
	ErrInvalidGoogleToken          = errors.New("invalid Google token")
	ErrUserServiceUnavailable      = errors.New("user service unavailable")
	ErrUserCreationFailed          = errors.New("failed to create user")
	ErrUnexpectedUserServiceStatus = errors.New("unexpected user service status")
)

type GoogleAuthService struct {
	accessConf     *jwt.Config
	refreshConf    *jwt.Config
	userClient     userservice.UserServiceClient
	googleClientID string
}

func NewGoogleAuthService(accessConf, refreshConf *jwt.Config, userClient userservice.UserServiceClient, googleClientID string) *GoogleAuthService {
	return &GoogleAuthService{
		accessConf:     accessConf,
		refreshConf:    refreshConf,
		userClient:     userClient,
		googleClientID: googleClientID,
	}
}

func (s *GoogleAuthService) Authenticate(ctx context.Context, idToken string) (jwt.Pair, error) {
	info, err := oauth.VerifyGoogleIDTokenFunc(ctx, idToken, s.googleClientID)
	if err != nil {
		return jwt.Pair{}, fmt.Errorf("%w: %v", ErrInvalidGoogleToken, err)
	}

	userResp, err := s.userClient.GetUserByProvider(ctx, &userservice.GetUserByProviderRequest{
		Provider:   "google",
		ProviderId: &pb.UUID{Value: info.Sub},
	})
	if err != nil {
		return jwt.Pair{}, fmt.Errorf("%w: %v", ErrUserServiceUnavailable, err)
	}

	var userID uuid.UUID
	var name, username string

	if userResp.Status == userservice.GetUserResponseStatus_SUCCESS {
		userID = uuid.MustParse(userResp.UserId.GetValue())
		name = *userResp.Name
		username = *userResp.Username
	} else if userResp.Status == userservice.GetUserResponseStatus_NOT_FOUND {
		emailResp, err := s.userClient.GetUserByEmail(ctx, &userservice.GetUserByEmailRequest{Email: info.Email})
		if err != nil {
			return jwt.Pair{}, fmt.Errorf("%w: %v", ErrUserServiceUnavailable, err)
		}

		if emailResp.Status == userservice.GetUserResponseStatus_SUCCESS {
			userID = uuid.MustParse(emailResp.UserId.GetValue())
			name = *emailResp.Name
			username = *emailResp.Username
		} else if emailResp.Status == userservice.GetUserResponseStatus_NOT_FOUND {
			username = strings.Split(info.Email, "@")[0]
			name = info.Name

			createResp, err := s.userClient.CreateUserWithProvider(ctx, &userservice.CreateUserWithProviderRequest{
				Provider:   "google",
				ProviderId: info.Sub,
				Name:       name,
				Username:   username,
			})
			if err != nil {
				return jwt.Pair{}, fmt.Errorf("%w: %v", ErrUserCreationFailed, err)
			}
			if createResp.Status != userservice.CreateUserStatus_CREATED {
				return jwt.Pair{}, fmt.Errorf("%w: status=%v", ErrUserCreationFailed, createResp.Status)
			}
			userID = uuid.MustParse(createResp.UserId.Value)
			name = *createResp.Name
			username = *createResp.Username
		} else {
			return jwt.Pair{}, fmt.Errorf("%w: status=%v", ErrUnexpectedUserServiceStatus, emailResp.Status)
		}
	} else {
		return jwt.Pair{}, fmt.Errorf("%w: status=%v", ErrUnexpectedUserServiceStatus, userResp.Status)
	}

	claims := jwt.Claims{
		"sub":      userID.String(),
		"name":     name,
		"username": username,
	}
	return s.generateTokenPair(claims)
}

func (s *GoogleAuthService) generateTokenPair(claims jwt.Claims) (jwt.Pair, error) {
	var pair jwt.Pair
	var err error

	if pair.Access, err = jwt.Generate(s.accessConf, claims); err != nil {
		return jwt.Pair{}, ErrAccessGeneration
	}
	if pair.Refresh, err = jwt.Generate(s.refreshConf, claims); err != nil {
		return jwt.Pair{}, ErrRefreshGeneration
	}
	return pair, nil
}
