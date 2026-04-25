package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSignInRepository struct {
	mock.Mock
}

func (m *MockSignInRepository) FindKey(ctx context.Context, key uuid.UUID) (*storage.AuthData, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuthData), args.Error(1)
}

func (m *MockSignInRepository) Remove(ctx context.Context, key uuid.UUID) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockSignInRepository) Update(ctx context.Context, data *storage.AuthData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func TestSignIn_ExistingUser_Success(t *testing.T) {
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

	userID := uuid.New()
	signInKey := uuid.New()
	code := "123456"
	data := &storage.AuthData{
		AuthKey:  signInKey,
		UserId:   userID,
		Email:    "test@example.com",
		Name:     "John",
		Username: "john_doe",
		Code:     code,
	}

	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signInKey).Return(data, nil)
	repo.On("Remove", mock.Anything, signInKey).Return(nil)

	service := services.NewSignInService(repo, accessConf, refreshConf)

	pair, err := service.SignIn(context.Background(), signInKey, code)

	assert.NoError(t, err)
	assert.NotEmpty(t, pair.Access)
	assert.NotEmpty(t, pair.Refresh)

	repo.AssertExpectations(t)
}

func TestSignIn_WrongCode(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signInKey := uuid.New()
	data := &storage.AuthData{
		AuthKey: signInKey,
		UserId:  uuid.New(),
		Code:    "123456",
	}

	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signInKey).Return(data, nil)

	service := services.NewSignInService(repo, accessConf, refreshConf)

	_, err := service.SignIn(context.Background(), signInKey, "wrong")

	assert.Error(t, err)
	assert.Equal(t, services.ErrWrongCode, err)
	repo.AssertNotCalled(t, "Remove")
}

func TestSignIn_KeyNotFound(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signInKey := uuid.New()
	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signInKey).Return(nil, storage.ErrAuthKeyNotFound)

	service := services.NewSignInService(repo, accessConf, refreshConf)

	_, err := service.SignIn(context.Background(), signInKey, "123456")

	assert.Error(t, err)
	assert.Equal(t, services.ErrAuthKeyNotFound, err)
}

func TestSignIn_UserNotFound(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signInKey := uuid.New()
	code := "123456"
	data := &storage.AuthData{
		AuthKey: signInKey,
		UserId:  uuid.Nil, // нет пользователя
		Code:    code,
	}

	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signInKey).Return(data, nil)

	service := services.NewSignInService(repo, accessConf, refreshConf)

	_, err := service.SignIn(context.Background(), signInKey, code)

	assert.Error(t, err)
	assert.Equal(t, services.ErrUserNotFound, err)
	repo.AssertNotCalled(t, "Remove")
}
