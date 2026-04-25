package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSignUp_Success(t *testing.T) {
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

	signUpKey := uuid.New()
	email := "new@example.com"
	name := "Test User"
	username := "testuser"
	createdUserID := uuid.New()

	data := &storage.AuthData{
		AuthKey:  signUpKey,
		Email:    email,
		UserId:   uuid.Nil,
		Verified: true, // важно: email подтверждён
	}

	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signUpKey).Return(data, nil)
	repo.On("Remove", mock.Anything, signUpKey).Return(nil)

	userClient := new(MockUserServiceClient)
	createResp := &userservice.CreateUserResponse{
		Status:   userservice.CreateUserStatus_CREATED,
		UserId:   &userservice.UUID{Value: createdUserID.String()},
		Name:     &name,
		Username: &username,
	}
	userClient.On("CreateUserWithEmail", mock.Anything, &userservice.CreateUserWithEmailRequest{
		Email:    email,
		Name:     name,
		Username: username,
	}).Return(createResp, nil)

	service := services.NewSignUpService(repo, userClient, accessConf, refreshConf)

	pair, err := service.SignUp(context.Background(), signUpKey, name, username)

	assert.NoError(t, err)
	assert.NotEmpty(t, pair.Access)
	assert.NotEmpty(t, pair.Refresh)

	repo.AssertExpectations(t)
	userClient.AssertExpectations(t)
}

func TestSignUp_KeyNotFound(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signUpKey := uuid.New()
	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signUpKey).Return(nil, storage.ErrAuthKeyNotFound)

	service := services.NewSignUpService(repo, nil, accessConf, refreshConf)

	_, err := service.SignUp(context.Background(), signUpKey, "Name", "username")

	assert.Error(t, err)
	assert.Equal(t, services.ErrAuthKeyNotFound, err)
}

func TestSignUp_EmailNotVerified(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signUpKey := uuid.New()
	data := &storage.AuthData{
		AuthKey:  signUpKey,
		Verified: false, // email не подтверждён
		UserId:   uuid.Nil,
	}
	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signUpKey).Return(data, nil)

	service := services.NewSignUpService(repo, nil, accessConf, refreshConf)

	_, err := service.SignUp(context.Background(), signUpKey, "Name", "username")

	assert.Error(t, err)
	assert.Equal(t, services.ErrEmailNotVerified, err)
}

func TestSignUp_UserAlreadyExists(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signUpKey := uuid.New()
	data := &storage.AuthData{
		AuthKey:  signUpKey,
		UserId:   uuid.New(),
		Verified: true,
	}
	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signUpKey).Return(data, nil)

	service := services.NewSignUpService(repo, nil, accessConf, refreshConf)

	_, err := service.SignUp(context.Background(), signUpKey, "Name", "username")

	assert.Error(t, err)
	assert.Equal(t, services.ErrUserAlreadyExists, err)
}

func TestSignUp_MissingFields(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	service := services.NewSignUpService(nil, nil, accessConf, refreshConf)

	_, err := service.SignUp(context.Background(), uuid.New(), "", "")

	assert.Error(t, err)
	assert.Equal(t, services.ErrMissingRequiredFields, err)
}

func TestSignUp_CreateUserFailed(t *testing.T) {
	accessConf := &jwt.Config{SigningMethod: "HS256", Lifetime: time.Hour, SymmetricKey: []byte("test")}
	refreshConf := &jwt.Config{SigningMethod: "HS256", Lifetime: 24 * time.Hour, SymmetricKey: []byte("test")}

	signUpKey := uuid.New()
	email := "new@example.com"
	name := "Test User"
	username := "testuser"

	data := &storage.AuthData{
		AuthKey:  signUpKey,
		Email:    email,
		UserId:   uuid.Nil,
		Verified: true,
	}

	repo := new(MockSignInRepository)
	repo.On("FindKey", mock.Anything, signUpKey).Return(data, nil)

	userClient := new(MockUserServiceClient)
	createResp := &userservice.CreateUserResponse{
		Status: userservice.CreateUserStatus_CREATE_FAILED,
	}
	userClient.On("CreateUserWithEmail", mock.Anything, mock.Anything).Return(createResp, nil)

	service := services.NewSignUpService(repo, userClient, accessConf, refreshConf)

	_, err := service.SignUp(context.Background(), signUpKey, name, username)

	assert.Error(t, err)
	assert.Equal(t, services.ErrCreateUserFailed, err)
}
