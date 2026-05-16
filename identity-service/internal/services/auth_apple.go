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
	ErrInvalidAppleToken = errors.New("invalid Apple token")
)

type AppleUserData struct {
	Name *struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name,omitempty"`
}

type AppleAuthService struct {
	accessConf    *jwt.Config
	refreshConf   *jwt.Config
	userClient    userservice.UserServiceClient
	appleClientID string
}

func NewAppleAuthService(accessConf, refreshConf *jwt.Config, userClient userservice.UserServiceClient, appleClientID string) *AppleAuthService {
	return &AppleAuthService{
		accessConf:    accessConf,
		refreshConf:   refreshConf,
		userClient:    userClient,
		appleClientID: appleClientID,
	}
}

func (s *AppleAuthService) Authenticate(ctx context.Context, idToken string, userData *AppleUserData) (jwt.Pair, error) {
	info, err := oauth.VerifyAppleIDTokenFunc(ctx, idToken, s.appleClientID)
	if err != nil {
		return jwt.Pair{}, fmt.Errorf("%w: %v", ErrInvalidAppleToken, err)
	}

	userResp, err := s.userClient.GetUserByProvider(ctx, &userservice.GetUserByProviderRequest{
		Provider:   "apple",
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
			// ✅ Пользователь с таким email уже есть — привязываем Apple provider
			userID = uuid.MustParse(emailResp.UserId.GetValue())
			name = *emailResp.Name
			username = *emailResp.Username

			addResp, err := s.userClient.AddProviderToUser(ctx, &userservice.AddProviderToUserRequest{
				UserId:     emailResp.UserId,
				Provider:   "apple",
				ProviderId: info.Sub,
			})
			if err != nil {
				return jwt.Pair{}, fmt.Errorf("add provider to user: %w", err)
			}
			if addResp.Status != userservice.AddProviderToUserStatus_ADD_PROVIDER_SUCCESS {
				if addResp.Status == userservice.AddProviderToUserStatus_ADD_PROVIDER_FAILED {
					// Провайдер уже привязан к другому пользователю
					return jwt.Pair{}, ErrProviderAlreadyLinked
				}
				return jwt.Pair{}, fmt.Errorf("add provider failed: status=%v", addResp.Status)
			}
		} else if emailResp.Status == userservice.GetUserResponseStatus_NOT_FOUND {
			fullName := ""
			if userData != nil && userData.Name != nil {
				fullName = strings.TrimSpace(userData.Name.FirstName + " " + userData.Name.LastName)
			}
			if fullName == "" {
				fullName = strings.Split(info.Email, "@")[0]
			}
			username = strings.Split(info.Email, "@")[0]

			createResp, err := s.userClient.CreateUserWithProvider(ctx, &userservice.CreateUserWithProviderRequest{
				Provider:   "apple",
				ProviderId: info.Sub,
				Name:       fullName,
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

func (s *AppleAuthService) generateTokenPair(claims jwt.Claims) (jwt.Pair, error) {
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
