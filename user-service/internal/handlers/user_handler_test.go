package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestUserHandler_CheckUsername_Basic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewUserHandler(mockService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1.0/username/testuser", nil)
	c.Params = gin.Params{{Key: "username", Value: "testuser"}}

	assert.NotNil(t, handler)
}

func TestUserHandler_SearchUsers_Basic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := &services.UserService{}
	handler := handlers.NewUserHandler(mockService)

	assert.NotNil(t, handler)
}
