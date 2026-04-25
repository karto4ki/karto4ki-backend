package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSignInSendCodeRepository struct {
	mock.Mock
}

func (m *MockSignInSendCodeRepository) FindKeyByEmail(ctx context.Context, email string) (*storage.AuthData, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuthData), args.Error(1)
}

func (m *MockSignInSendCodeRepository) Store(ctx context.Context, data *storage.AuthData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func TestSignInSendCode_Success_ExistingUser(t *testing.T) {
	ttl := 5 * time.Minute
	email := "existing@example.com"
	userID := uuid.New()
	name := "John Doe"
	username := "johndoe"

	repo := new(MockSignInSendCodeRepository)
	emailSender := new(MockEmailSender)
	userClient := new(MockUserServiceClient)

	repo.On("FindKeyByEmail", mock.Anything, email).Return(nil, storage.ErrAuthKeyNotFound)

	userResp := &userservice.GetUserResponse{
		Status:   userservice.GetUserResponseStatus_SUCCESS,
		UserId:   &userservice.UUID{Value: userID.String()},
		Name:     &name,
		Username: &username,
	}
	userClient.On("GetUserByEmail", mock.Anything, &userservice.GetUserByEmailRequest{Email: email}).Return(userResp, nil)

	emailSender.On("SendEmail", mock.Anything, email, mock.MatchedBy(func(msg string) bool {
		return len(msg) > 0
	})).Return(nil)

	repo.On("Store", mock.Anything, mock.MatchedBy(func(data *storage.AuthData) bool {
		return data.Email == email && data.UserId == userID && data.Name == name && data.Username == username && data.Code != ""
	})).Return(nil)

	service := services.NewSendCodeService(&ttl, repo, emailSender, userClient)

	key, isExist, err := service.SignInSendCode(context.Background(), email)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, key)
	assert.True(t, isExist)

	repo.AssertExpectations(t)
	emailSender.AssertExpectations(t)
	userClient.AssertExpectations(t)
}

func TestSignInSendCode_Success_NewUser(t *testing.T) {
	ttl := 5 * time.Minute
	email := "new@example.com"

	repo := new(MockSignInSendCodeRepository)
	emailSender := new(MockEmailSender)
	userClient := new(MockUserServiceClient)

	repo.On("FindKeyByEmail", mock.Anything, email).Return(nil, storage.ErrAuthKeyNotFound)

	userResp := &userservice.GetUserResponse{
		Status: userservice.GetUserResponseStatus_NOT_FOUND,
	}
	userClient.On("GetUserByEmail", mock.Anything, &userservice.GetUserByEmailRequest{Email: email}).Return(userResp, nil)

	emailSender.On("SendEmail", mock.Anything, email, mock.Anything).Return(nil)

	repo.On("Store", mock.Anything, mock.MatchedBy(func(data *storage.AuthData) bool {
		return data.Email == email && data.UserId == uuid.Nil && data.Name == "" && data.Username == ""
	})).Return(nil)

	service := services.NewSendCodeService(&ttl, repo, emailSender, userClient)

	key, isExist, err := service.SignInSendCode(context.Background(), email)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, key)
	assert.False(t, isExist)

	repo.AssertExpectations(t)
	emailSender.AssertExpectations(t)
	userClient.AssertExpectations(t)
}

func TestSignInSendCode_FrequencyExceeded(t *testing.T) {
	ttl := 5 * time.Minute
	email := "test@example.com"
	lastReq := time.Now().UTC().Add(-1 * time.Minute)

	existingData := &storage.AuthData{
		AuthKey:     uuid.New(),
		LastRequest: lastReq,
		Email:       email,
		UserId:      uuid.New(),
	}

	repo := new(MockSignInSendCodeRepository)
	repo.On("FindKeyByEmail", mock.Anything, email).Return(existingData, nil)

	service := services.NewSendCodeService(&ttl, repo, nil, nil)

	key, isExist, err := service.SignInSendCode(context.Background(), email)

	assert.Error(t, err)
	assert.Equal(t, services.ErrSendCodeFreqExceeded, err)
	assert.Equal(t, uuid.Nil, key)
	assert.True(t, isExist)
}
