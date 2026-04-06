package tests

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/oauth"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// MockSignUpRepository implements SignUpRepository
type MockSignUpRepository struct {
	mock.Mock
}

func (m *MockSignUpRepository) Store(ctx context.Context, data *storage.AuthData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockSignUpRepository) FindByKey(ctx context.Context, key uuid.UUID) (*storage.AuthData, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuthData), args.Error(1)
}

func (m *MockSignUpRepository) Delete(ctx context.Context, key uuid.UUID) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockSignUpRepository) GetLastRequest(ctx context.Context, email string) (time.Time, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(time.Time), args.Error(1)
}

func (m *MockSignUpRepository) SetLastRequest(ctx context.Context, email string, t time.Time) error {
	args := m.Called(ctx, email, t)
	return args.Error(0)
}

type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) SendEmail(ctx context.Context, to, message string) error {
	args := m.Called(ctx, to, message)
	return args.Error(0)
}

// MockUserServiceClientForSignUp implements userservice.UserServiceClient (only needed methods)
type MockUserServiceClient struct {
	mock.Mock
}

// CreateUserWithProvider implements userservice.UserServiceClient.
func (m *MockUserServiceClient) CreateUserWithProvider(ctx context.Context, in *userservice.CreateUserWithProviderRequest, opts ...grpc.CallOption) (*userservice.CreateUserResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*userservice.CreateUserResponse), args.Error(1)
}

// GetUserByProvider implements userservice.UserServiceClient.
func (m *MockUserServiceClient) GetUserByProvider(ctx context.Context, in *userservice.GetUserByProviderRequest, opts ...grpc.CallOption) (*userservice.GetUserResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*userservice.GetUserResponse), args.Error(1)
}

func (m *MockUserServiceClient) GetUserByEmail(ctx context.Context, req *userservice.GetUserByEmailRequest, opts ...grpc.CallOption) (*userservice.GetUserResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*userservice.GetUserResponse), args.Error(1)
}

func (m *MockUserServiceClient) CreateUserWithEmail(ctx context.Context, req *userservice.CreateUserWithEmailRequest, opts ...grpc.CallOption) (*userservice.CreateUserResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*userservice.CreateUserResponse), args.Error(1)
}

type MockGoogleValidator struct {
	mock.Mock
}

func (m *MockGoogleValidator) VerifyGoogleIDToken(ctx context.Context, idToken, clientID string) (*oauth.GoogleTokenInfo, error) {
	args := m.Called(ctx, idToken, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.GoogleTokenInfo), args.Error(1)
}

// MockAppleValidator replaces the real validation function.
type MockAppleValidator struct {
	mock.Mock
}

func (m *MockAppleValidator) VerifyAppleIDToken(ctx context.Context, idToken, clientID string) (*oauth.AppleTokenClaims, error) {
	args := m.Called(ctx, idToken, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth.AppleTokenClaims), args.Error(1)
}
