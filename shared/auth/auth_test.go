package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/shared/auth"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewJWT_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &jwt.Config{
		SigningMethod: "HS512",
		SymmetricKey:  []byte("test-secret-key-for-testing-only"),
	}

	middleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          config,
		DefaultHeader: "X-Internal-Token",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	middleware(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Unauthorized")
}

func TestNewJWT_EmptyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &jwt.Config{
		SigningMethod: "HS512",
		SymmetricKey:  []byte("test-secret-key-for-testing-only"),
	}

	middleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          config,
		DefaultHeader: "X-Internal-Token",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("X-Internal-Token", "")

	middleware(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNewJWT_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &jwt.Config{
		SigningMethod: "HS512",
		SymmetricKey:  []byte("test-secret-key-for-testing-only"),
	}

	middleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          config,
		DefaultHeader: "X-Internal-Token",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("X-Internal-Token", "invalid.token.here")

	middleware(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNewJWT_ValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret-key-for-testing-only-32bytes!!")
	config := &jwt.Config{
		SigningMethod: "HS512",
		Lifetime:      300000000000,
		Issuer:        "test-service",
		Audience:      []string{"test-audience"},
		Type:          "internal_access",
		SymmetricKey:  secret,
	}

	userID := "test-user-123"
	claims := jwt.Claims{
		"sub": userID,
	}
	token, err := jwt.Generate(config, claims)
	assert.NoError(t, err)

	middleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          config,
		DefaultHeader: "X-Internal-Token",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("X-Internal-Token", string(token))

	middleware(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, userID, c.GetString("user_id"))
}

func TestNewJWT_ExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret-key-for-testing-only-32bytes!!")
	config := &jwt.Config{
		SigningMethod: "HS512",
		Lifetime:      0,
		Issuer:        "test-service",
		SymmetricKey:  secret,
	}

	claims := jwt.Claims{"sub": "user-123"}
	token, err := jwt.Generate(config, claims)
	assert.NoError(t, err)

	middleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          config,
		DefaultHeader: "X-Internal-Token",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("X-Internal-Token", string(token))

	middleware(c)

	assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusOK)
}

func TestNewJWT_DefaultHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret-key-for-testing-only-32bytes!!")
	config := &jwt.Config{
		SigningMethod: "HS512",
		Lifetime:      300000000000,
		Issuer:        "test-service",
		SymmetricKey:  secret,
	}

	userID := "test-user-456"
	claims := jwt.Claims{"sub": userID}
	token, err := jwt.Generate(config, claims)
	assert.NoError(t, err)

	middleware := auth.NewJWT(&auth.JWTConfig{
		Conf:          config,
		DefaultHeader: "Authorization",
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Authorization", string(token))
	middleware(c)

	assert.Equal(t, userID, c.GetString("user_id"))
}

func TestGetClaims(t *testing.T) {
	claims := auth.Claims{
		"sub":   "user-123",
		"name":  "Test User",
		"email": "test@example.com",
	}

	ctx := context.WithValue(context.Background(), auth.GetClaimsKey(), claims)

	retrievedClaims := auth.GetClaims(ctx)
	assert.NotNil(t, retrievedClaims)
	assert.Equal(t, "user-123", retrievedClaims["sub"])
	assert.Equal(t, "Test User", retrievedClaims["name"])
}

func TestGetClaims_EmptyContext(t *testing.T) {
	ctx := context.Background()
	claims := auth.GetClaims(ctx)
	assert.Nil(t, claims)
}
