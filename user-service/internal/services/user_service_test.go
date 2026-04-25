package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	args := m.Called(ctx, provider, providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) CreateUserWithEmail(ctx context.Context, email, name, username string) (*models.User, error) {
	args := m.Called(ctx, email, name, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) CreateUserWithProvider(ctx context.Context, provider, providerID, name, username string) (*models.User, error) {
	args := m.Called(ctx, provider, providerID, name, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, id uuid.UUID, name, username string, notificationEnabled bool) (*models.User, error) {
	args := m.Called(ctx, id, name, username, notificationEnabled)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockUserRepository) UpdatePhoto(ctx context.Context, id uuid.UUID, photoURL string) (*models.User, error) {
	args := m.Called(ctx, id, photoURL)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) DeletePhoto(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) SearchUsers(ctx context.Context, req storage.SearchUsersRequest) (*storage.SearchUsersResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.SearchUsersResponse), args.Error(1)
}

func createTestUser() *models.User {
	email := "test@example.com"
	return &models.User{
		ID:                  uuid.New(),
		Email:               &email,
		Name:                "Test User",
		Username:            "testuser",
		PhotoURL:            nil,
		CreatedAt:           time.Now(),
		NotificationEnabled: true,
		Provider:            nil,
		ProviderId:          nil,
	}
}

func TestUserService_GetUserByID_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	expectedUser := createTestUser()
	ctx := context.Background()

	mockRepo.On("GetUserByID", ctx, expectedUser.ID).Return(expectedUser, nil)

	user, err := userService.GetUserByID(ctx, expectedUser.ID)

	assert.NoError(t, err)
	assert.Equal(t, expectedUser.ID, user.ID)
	assert.Equal(t, expectedUser.Username, user.Username)
	mockRepo.AssertExpectations(t)
}

func TestUserService_GetUserByID_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	mockRepo.On("GetUserByID", ctx, userID).Return(nil, storage.ErrNotFound)

	user, err := userService.GetUserByID(ctx, userID)

	assert.ErrorIs(t, err, services.ErrNotFound)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_GetUserByID_DatabaseError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()
	dbError := errors.New("database connection failed")

	mockRepo.On("GetUserByID", ctx, userID).Return(nil, dbError)

	user, err := userService.GetUserByID(ctx, userID)

	assert.Error(t, err)
	assert.Equal(t, dbError, err)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_GetUserByUsername_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	expectedUser := createTestUser()
	ctx := context.Background()

	mockRepo.On("GetUserByUsername", ctx, expectedUser.Username).Return(expectedUser, nil)

	user, err := userService.GetUserByUsername(ctx, expectedUser.Username)

	assert.NoError(t, err)
	assert.Equal(t, expectedUser.Username, user.Username)
	mockRepo.AssertExpectations(t)
}

func TestUserService_GetUserByUsername_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	ctx := context.Background()

	mockRepo.On("GetUserByUsername", ctx, "nonexistent").Return(nil, storage.ErrNotFound)

	user, err := userService.GetUserByUsername(ctx, "nonexistent")

	assert.ErrorIs(t, err, services.ErrNotFound)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_UpdateUser_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	newName := "Updated Name"
	newUsername := "updateduser"
	ctx := context.Background()

	updatedUser := createTestUser()
	updatedUser.Name = newName
	updatedUser.Username = newUsername

	mockRepo.On("UpdateUser", ctx, userID, newName, newUsername, true).Return(updatedUser, nil)

	user, err := userService.UpdateUser(ctx, userID, newName, newUsername, true)

	assert.NoError(t, err)
	assert.Equal(t, newName, user.Name)
	assert.Equal(t, newUsername, user.Username)
	mockRepo.AssertExpectations(t)
}

func TestUserService_UpdateUser_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	mockRepo.On("UpdateUser", ctx, userID, "name", "username", true).Return(nil, storage.ErrNotFound)

	user, err := userService.UpdateUser(ctx, userID, "name", "username", true)

	assert.ErrorIs(t, err, services.ErrNotFound)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_UpdateUser_AlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	mockRepo.On("UpdateUser", ctx, userID, "name", "existing_username", true).Return(nil, storage.ErrAlreadyExists)

	user, err := userService.UpdateUser(ctx, userID, "name", "existing_username", true)

	assert.ErrorIs(t, err, services.ErrAlreadyExists)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_DeleteUser_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	mockRepo.On("DeleteUser", ctx, userID).Return(nil)

	err := userService.DeleteUser(ctx, userID)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestUserService_DeleteUser_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	mockRepo.On("DeleteUser", ctx, userID).Return(storage.ErrNotFound)

	err := userService.DeleteUser(ctx, userID)

	assert.ErrorIs(t, err, services.ErrNotFound)
	mockRepo.AssertExpectations(t)
}

func TestUserService_ExistsByUsername_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	ctx := context.Background()
	user := createTestUser()

	mockRepo.On("GetUserByUsername", ctx, user.Username).Return(user, nil)

	exists, err := userService.ExistsByUsername(ctx, user.Username)

	assert.NoError(t, err)
	assert.True(t, exists)
	mockRepo.AssertExpectations(t)
}

func TestUserService_ExistsByUsername_False(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	ctx := context.Background()

	mockRepo.On("GetUserByUsername", ctx, "nonexistent").Return(nil, storage.ErrNotFound)

	exists, err := userService.ExistsByUsername(ctx, "nonexistent")

	assert.NoError(t, err)
	assert.False(t, exists)
	mockRepo.AssertExpectations(t)
}

func TestUserService_ExistsByUsername_Error(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	ctx := context.Background()
	dbError := errors.New("database error")

	mockRepo.On("GetUserByUsername", ctx, "username").Return(nil, dbError)

	exists, err := userService.ExistsByUsername(ctx, "username")

	assert.Error(t, err)
	assert.False(t, exists)
	mockRepo.AssertExpectations(t)
}

func TestUserService_UpdatePhoto_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	photoURL := "https://example.com/photo.jpg"
	ctx := context.Background()

	updatedUser := createTestUser()
	updatedUser.PhotoURL = &photoURL

	mockRepo.On("UpdatePhoto", ctx, userID, photoURL).Return(updatedUser, nil)

	user, err := userService.UpdatePhoto(ctx, userID, photoURL)

	assert.NoError(t, err)
	assert.Equal(t, photoURL, *user.PhotoURL)
	mockRepo.AssertExpectations(t)
}

func TestUserService_UpdatePhoto_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	mockRepo.On("UpdatePhoto", ctx, userID, "https://example.com/photo.jpg").Return(nil, storage.ErrNotFound)

	user, err := userService.UpdatePhoto(ctx, userID, "https://example.com/photo.jpg")

	assert.ErrorIs(t, err, services.ErrNotFound)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_DeletePhoto_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userID := uuid.New()
	ctx := context.Background()

	updatedUser := createTestUser()
	updatedUser.PhotoURL = nil

	mockRepo.On("DeletePhoto", ctx, userID).Return(updatedUser, nil)

	user, err := userService.DeletePhoto(ctx, userID)

	assert.NoError(t, err)
	assert.Nil(t, user.PhotoURL)
	mockRepo.AssertExpectations(t)
}

func TestUserService_SearchUsers_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	ctx := context.Background()
	name := "test"
	req := storage.SearchUsersRequest{
		Name:   &name,
		Offset: 0,
		Limit:  10,
	}

	expectedResponse := &storage.SearchUsersResponse{
		Users:  []models.User{*createTestUser()},
		Offset: 0,
		Count:  1,
	}

	mockRepo.On("SearchUsers", ctx, req).Return(expectedResponse, nil)

	response, err := userService.SearchUsers(ctx, req)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(response.Users))
	assert.Equal(t, 1, response.Count)
	mockRepo.AssertExpectations(t)
}
