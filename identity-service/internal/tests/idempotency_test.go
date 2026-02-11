package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockIdempotencyStorage struct {
	mu    sync.RWMutex
	data  map[string]*storage.CapturedResponse
	locks map[string]string
}

func newMockIdempotencyStorage() services.IdempotencyStorage {
	return &mockIdempotencyStorage{
		data:  make(map[string]*storage.CapturedResponse),
		locks: make(map[string]string),
	}
}

func (m *mockIdempotencyStorage) AcquireLock(_ context.Context, key string, ttl time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if token, exists := m.locks[key]; exists {
		return "", &mockLockError{key: key, token: token}
	}

	token := generateLockToken(key)
	m.locks[key] = token

	return token, nil
}

func (m *mockIdempotencyStorage) ReleaseLock(_ context.Context, key, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existingToken, exists := m.locks[key]; exists && existingToken == token {
		delete(m.locks, key)
		return nil
	}

	return &mockLockError{key: key, token: token, released: true}
}

func (m *mockIdempotencyStorage) Get(_ context.Context, key string) (*storage.CapturedResponse, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resp, ok := m.data[key]
	return resp, ok, nil
}

func (m *mockIdempotencyStorage) Store(_ context.Context, key string, resp *storage.CapturedResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = resp
	return nil
}

func generateLockToken(key string) string {
	return "lock-token-" + key + "-" + time.Now().Format("150405.000")
}

type mockLockError struct {
	key      string
	token    string
	released bool
}

func (e *mockLockError) Error() string {
	if e.released {
		return "lock not found or token mismatch for key: " + e.key
	}
	return "lock already acquired for key: " + e.key + " with token: " + e.token
}

func TestStoresResponse(t *testing.T) {
	// Arrange
	r, storage := setUp()
	r.POST("/200-with-body", func(c *gin.Context) {
		c.JSON(http.StatusOK, restapi.SuccessResponse{
			Data: gin.H{
				"word": "Success Data",
			},
		})
	})

	const idempotencyKey = "d6f67723-cf79-46a2-9864-ab0d541cd434"

	// Act
	resp := execute(r, "/200-with-body", idempotencyKey)
	captured, ok, err := storage.Get(context.Background(), idempotencyKey)

	// Assert
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, captured.StatusCode)
	assert.JSONEq(t, resp.Body.String(), string(captured.Body))
}

func TestReturnsStored(t *testing.T) {
	// Arrange
	r, repo := setUp()
	r.POST("/200", func(_ *gin.Context) {
		assert.FailNow(t, "This code is not to re-execute")
	})

	const idempotencyKey = "2e89f9fc-5596-4a9c-8177-3b4ce3853b17"
	cachedResp := &storage.CapturedResponse{
		StatusCode: 200,
		Headers: http.Header{
			"Custom-Header": []string{"idk"},
			"Content-Type":  []string{"application/octet-stream"},
		},
		Body: []byte{69},
	}

	err := repo.Store(context.Background(), idempotencyKey, cachedResp)
	require.NoError(t, err)

	// Act
	resp := execute(r, "/200", idempotencyKey)

	// Assert
	assert.Equal(t, cachedResp.StatusCode, resp.Code)
	assert.Equal(t, cachedResp.Headers.Get("Custom-Header"), resp.Header().Get("Custom-Header"))
	assert.Equal(t, cachedResp.Body, resp.Body.Bytes())
}

func TestSlowExecutionFastRetry(t *testing.T) {
	// Arrange
	r, storage := setUp()

	callCount := 0
	var mu sync.Mutex

	r.POST("/200-slow", func(c *gin.Context) {
		mu.Lock()
		callCount++
		currentCall := callCount
		mu.Unlock()

		if currentCall == 1 {
			time.Sleep(200 * time.Millisecond)
		}

		c.String(200, "response-%d", currentCall)
	})

	const idempotencyKey = "2e89f9fc-5596-4a9c-8177-3b4ce3853b17"

	wg := sync.WaitGroup{}
	results := make([]*httptest.ResponseRecorder, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = execute(r, "/200-slow", idempotencyKey)
		}(i)
	}
	wg.Wait()

	successCount := 0
	errorCount := 0

	for i := 0; i < len(results); i++ {
		if results[i].Code == 200 {
			successCount++
		} else if results[i].Code == 409 {
			errorCount++
		}
	}

	assert.Equal(t, 1, successCount)
	assert.Equal(t, 2, errorCount)

	var successResponse *httptest.ResponseRecorder
	for i := 0; i < len(results); i++ {
		if results[i].Code == 200 {
			successResponse = results[i]
			break
		}
	}

	require.NotNil(t, successResponse)
	assert.Equal(t, "response-1", successResponse.Body.String())

	for i := 0; i < len(results); i++ {
		if results[i].Code == 409 {
			assert.Contains(t, results[i].Body.String(), "request in progress",
				"409 error should contain 'request in progress'")
			assert.Contains(t, results[i].Body.String(), "Another request with same idempotency key",
				"409 error should contain proper message")
		}
	}

	assert.Equal(t, 1, callCount)

	time.Sleep(50 * time.Millisecond)
	cached, ok, err := storage.Get(context.Background(), idempotencyKey)
	require.NoError(t, err)
	if ok && cached != nil {
		assert.Equal(t, "response-1", string(cached.Body))
	}
}

func TestMissingIdempotencyKey(t *testing.T) {
	r, _ := setUp()
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	respRecorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(respRecorder, req)

	assert.Equal(t, http.StatusBadRequest, respRecorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(respRecorder.Body.Bytes(), &response)
	if err == nil {
		assert.Equal(t, services.ErrIdempotencyKeyMissing, response["error_type"])
	}
}

func TestDuplicateRequestReturnsCached(t *testing.T) {
	r, _ := setUp()

	callCount := 0
	r.POST("/duplicate-test", func(c *gin.Context) {
		callCount++
		c.JSON(http.StatusOK, gin.H{"count": callCount})
	})

	const idempotencyKey = "duplicate-test-key"

	resp1 := execute(r, "/duplicate-test", idempotencyKey)

	time.Sleep(50 * time.Millisecond)

	resp2 := execute(r, "/duplicate-test", idempotencyKey)

	assert.Equal(t, resp1.Code, resp2.Code)
	assert.Equal(t, resp1.Body.String(), resp2.Body.String())

	assert.Equal(t, 1, callCount)
}

func TestLockConflict(t *testing.T) {
	storage := newMockIdempotencyStorage()

	token, err := storage.AcquireLock(context.Background(), "test-lock-key", 30*time.Second)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, err = storage.AcquireLock(context.Background(), "test-lock-key", 30*time.Second)
	assert.Error(t, err)

	err = storage.ReleaseLock(context.Background(), "test-lock-key", token)
	assert.NoError(t, err)

	token2, err := storage.AcquireLock(context.Background(), "test-lock-key", 30*time.Second)
	assert.NoError(t, err)
	assert.NotEmpty(t, token2)

	err = storage.ReleaseLock(context.Background(), "test-lock-key", token2)
	assert.NoError(t, err)
}

func execute(r *gin.Engine, path, idempotencyKey string) *httptest.ResponseRecorder {
	respRecorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(services.HeaderIdempotencyKey, idempotencyKey)

	r.ServeHTTP(respRecorder, req)
	return respRecorder
}

func setUp() (*gin.Engine, services.IdempotencyStorage) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	mockStorage := newMockIdempotencyStorage()

	config := services.MiddlewareConfig{
		Storage:    mockStorage,
		LockTTL:    30 * time.Second,
		ResultTTL:  24 * time.Hour,
		RetryCount: 3,
		RetryDelay: 10 * time.Millisecond,
	}

	r.Use(services.NewMiddleware(config))
	return r, mockStorage
}
