package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockRevokeRepository struct {
	mock.Mock
}

func (m *MockRevokeRepository) Revoke(ctx context.Context, token jwt.Token) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRevokeRepository) IsRevoked(ctx context.Context, token jwt.Token) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func createTestJWTConfig() (*jwt.Config, *jwt.Config) {
	accessConfig := &jwt.Config{
		SigningMethod: "HS512",
		Lifetime:      15 * time.Minute,
		Issuer:        "test-issuer",
		Type:          "access",
	}
	accessConfig.SymmetricKey = []byte("test-access-secret")

	refreshConfig := &jwt.Config{
		SigningMethod: "HS512",
		Lifetime:      24 * time.Hour,
		Issuer:        "test-issuer",
		Type:          "refresh",
	}
	refreshConfig.SymmetricKey = []byte("test-refresh-secret")

	return accessConfig, refreshConfig
}

func TestRefreshService_Success(t *testing.T) {
	// Arrange
	accessConfig, refreshConfig := createTestJWTConfig()
	mockRepo := new(MockRevokeRepository)
	service := services.NewRefreshJWTService(accessConfig, refreshConfig, mockRepo)

	claims := jwt.Claims{
		"sub":      "user-123",
		"name":     "Test User",
		"username": "testuser",
	}
	refreshToken, err := jwt.Generate(refreshConfig, claims)
	assert.NoError(t, err)

	mockRepo.On("IsRevoked", mock.Anything, refreshToken).Return(false, nil)
	mockRepo.On("Revoke", mock.Anything, refreshToken).Return(nil)

	// Act
	ctx := context.Background()
	pair, err := service.Refresh(ctx, refreshToken)

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, pair.Access)
	assert.NotEmpty(t, pair.Refresh)
	assert.NotEqual(t, string(refreshToken), string(pair.Refresh)) // Новый токен

	mockRepo.AssertExpectations(t)
}

func TestRefreshService_ExpiredToken(t *testing.T) {
	// Arrange
	accessConfig, refreshConfig := createTestJWTConfig()
	mockRepo := new(MockRevokeRepository)
	service := services.NewRefreshJWTService(accessConfig, refreshConfig, mockRepo)

	expiredConfig := &jwt.Config{
		SigningMethod: "HS256",
		Lifetime:      -1 * time.Hour,
		Issuer:        "test-issuer",
		Type:          "refresh",
	}
	expiredConfig.SymmetricKey = []byte("test-refresh-secret")

	claims := jwt.Claims{"sub": "user-123"}
	expiredToken, err := jwt.Generate(expiredConfig, claims)
	assert.NoError(t, err)

	mockRepo.On("IsRevoked", mock.Anything, expiredToken).Return(false, nil)

	// Act
	ctx := context.Background()
	_, err = service.Refresh(ctx, expiredToken)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, services.ErrRefreshTokenExpired, err)
}

func TestRefreshService_RevokedToken(t *testing.T) {
	// Arrange
	accessConfig, refreshConfig := createTestJWTConfig()
	mockRepo := new(MockRevokeRepository)
	service := services.NewRefreshJWTService(accessConfig, refreshConfig, mockRepo)

	claims := jwt.Claims{"sub": "user-123"}
	refreshToken, err := jwt.Generate(refreshConfig, claims)
	assert.NoError(t, err)

	mockRepo.On("IsRevoked", mock.Anything, refreshToken).Return(true, nil)

	// Act
	ctx := context.Background()
	_, err = service.Refresh(ctx, refreshToken)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, services.ErrRefreshTokenInvalidated, err)
}

func TestRefreshService_InvalidToken(t *testing.T) {
	// Arrange
	accessConfig, refreshConfig := createTestJWTConfig()
	mockRepo := new(MockRevokeRepository)
	service := services.NewRefreshJWTService(accessConfig, refreshConfig, mockRepo)

	invalidToken := jwt.Token("invalid.jwt.token")
	mockRepo.On("IsRevoked", mock.Anything, invalidToken).Return(false, nil).Once()

	// Act
	ctx := context.Background()
	_, err := service.Refresh(ctx, invalidToken)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, services.ErrInvalidJWT, err)
	mockRepo.AssertExpectations(t)
}

func TestRefreshService_WrongTokenType(t *testing.T) {
	// Arrange
	accessConfig, refreshConfig := createTestJWTConfig()
	mockRepo := new(MockRevokeRepository)
	service := services.NewRefreshJWTService(accessConfig, refreshConfig, mockRepo)

	claims := jwt.Claims{"sub": "user-123", "typ": "access"}
	wrongTypeToken, err := jwt.Generate(accessConfig, claims)
	assert.NoError(t, err)

	mockRepo.On("IsRevoked", mock.Anything, wrongTypeToken).Return(false, nil).Once()

	// Act
	ctx := context.Background()
	_, err = service.Refresh(ctx, wrongTypeToken)

	// Assert
	assert.Error(t, err)

	assert.True(t,
		errors.Is(err, services.ErrInvalidTokenType) || errors.Is(err, services.ErrInvalidJWT),
	)

	mockRepo.AssertExpectations(t)
}
