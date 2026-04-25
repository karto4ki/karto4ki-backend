package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestProfileHandler_Basic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewProfileHandler(mockService)

	assert.NotNil(t, handler)
}

func TestProfileHandler_UpdateMyProfile_InvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewProfileHandler(mockService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/v1.0/me", bytes.NewBufferString("invalid json"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", uuid.New().String())

	handler.UpdateMyProfile(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestProfileHandler_GetMyProfile_InvalidUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewProfileHandler(mockService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1.0/me", nil)
	c.Set("user_id", "invalid-uuid")

	handler.GetMyProfile(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProfileHandler_DeleteMyProfile_Basic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewProfileHandler(mockService)

	assert.NotNil(t, handler)
}

func TestProfileHandler_UpdateProfilePhoto_InvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewProfileHandler(mockService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/v1.0/me/profile-photo", bytes.NewBufferString("invalid"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", uuid.New().String())

	handler.UpdateProfilePhoto(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestProfileHandler_UpdateProfilePhoto_MissingPhotoID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewProfileHandler(mockService)

	reqBody := map[string]interface{}{}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/v1.0/me/profile-photo", bytes.NewBuffer(jsonBody))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", uuid.New().String())

	handler.UpdateProfilePhoto(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
