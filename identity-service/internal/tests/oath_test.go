package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/oauth"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGoogleAuthService_Authenticate_ExistingUser(t *testing.T) {
	// Setup configs
	accessConf := &jwt.Config{
		SigningMethod: "HS256",
		Lifetime:      time.Hour,
		SymmetricKey:  []byte("test-secret"),
		Type:          "access",
	}
	refreshConf := &jwt.Config{
		SigningMethod: "HS256",
		Lifetime:      24 * time.Hour,
		SymmetricKey:  []byte("test-secret"),
		Type:          "refresh",
	}
	clientID := "test-client"
	idToken := "valid-token"
	email := "user@gmail.com"
	name := "Test User"
	userID := uuid.New()
	username := "testuser"

	// Mock validator
	mockValidator := new(MockGoogleValidator)
	oauth.VerifyGoogleIDTokenFunc = mockValidator.VerifyGoogleIDToken
	defer func() { oauth.VerifyGoogleIDTokenFunc = oauth.VerifyGoogleIDToken }() // restore

	mockValidator.On("VerifyGoogleIDToken", mock.Anything, idToken, clientID).
		Return(&oauth.GoogleTokenInfo{
			Sub:           "google-sub",
			Email:         email,
			EmailVerified: true,
			Name:          name,
		}, nil)

	// Mock user client
	mockUserClient := new(MockUserServiceClient)
	userResp := &userservice.GetUserResponse{
		Status:   userservice.GetUserResponseStatus_SUCCESS,
		UserId:   &userservice.UUID{Value: userID.String()},
		Name:     &name,
		Username: &username,
	}
	mockUserClient.On("GetUserByEmail", mock.Anything, &userservice.GetUserByEmailRequest{Email: email}).
		Return(userResp, nil)

	service := services.NewGoogleAuthService(accessConf, refreshConf, mockUserClient, clientID)

	pair, err := service.Authenticate(context.Background(), idToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, pair.Access)
	assert.NotEmpty(t, pair.Refresh)
	mockValidator.AssertExpectations(t)
	mockUserClient.AssertExpectations(t)
}

func TestGoogleAuthService_Authenticate_NewUser(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test"), Type: "access"}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test"), Type: "refresh"}
	clientID := "test-client"
	idToken := "new-user-token"
	email := "new@gmail.com"
	name := "New User"
	sub := "google-sub-456"

	mockValidator := new(MockGoogleValidator)
	oauth.VerifyGoogleIDTokenFunc = mockValidator.VerifyGoogleIDToken
	defer restoreGoogleValidator()

	mockValidator.On("VerifyGoogleIDToken", mock.Anything, idToken, clientID).
		Return(&oauth.GoogleTokenInfo{
			Sub:           sub,
			Email:         email,
			EmailVerified: true,
			Name:          name,
		}, nil)

	mockUserClient := new(MockUserServiceClient)
	// User not found
	mockUserClient.On("GetUserByEmail", mock.Anything, &userservice.GetUserByEmailRequest{Email: email}).
		Return(&userservice.GetUserResponse{Status: userservice.GetUserResponseStatus_NOT_FOUND}, nil)

	createdUserID := uuid.New()
	createResp := &userservice.CreateUserResponse{
		Status:   userservice.CreateUserStatus_CREATED,
		UserId:   &userservice.UUID{Value: createdUserID.String()},
		Name:     &name,
		Username: strPtr("new"),
	}
	mockUserClient.On("CreateUserWithProvider", mock.Anything, &userservice.CreateUserWithProviderRequest{
		Provider:   "google",
		ProviderId: sub,
		Name:       name,
		Username:   "new",
	}).Return(createResp, nil)

	service := services.NewGoogleAuthService(accessConf, refreshConf, mockUserClient, clientID)

	pair, err := service.Authenticate(context.Background(), idToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, pair.Access)
	assert.NotEmpty(t, pair.Refresh)
	mockValidator.AssertExpectations(t)
	mockUserClient.AssertExpectations(t)
}

func strPtr(s string) *string {
	return &s
}

func TestGoogleAuthService_Authenticate_InvalidToken(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test"), Type: "access"}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test"), Type: "refresh"}
	clientID := "test-client"
	idToken := "bad-token"

	mockValidator := new(MockGoogleValidator)
	oauth.VerifyGoogleIDTokenFunc = mockValidator.VerifyGoogleIDToken
	defer restoreGoogleValidator()

	mockValidator.On("VerifyGoogleIDToken", mock.Anything, idToken, clientID).
		Return(nil, errors.New("invalid token"))

	service := services.NewGoogleAuthService(accessConf, refreshConf, nil, clientID)

	pair, err := service.Authenticate(context.Background(), idToken)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, services.ErrInvalidGoogleToken))
	assert.Equal(t, jwt.Pair{}, pair)
	mockValidator.AssertExpectations(t)
}

func restoreGoogleValidator() {
	oauth.VerifyGoogleIDTokenFunc = oauth.VerifyGoogleIDToken
}
