package services

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/restapi"
)

const (
	HeaderIdempotencyKey     = "Idempotency-Key"
	ErrIdempotencyKeyMissing = "idempotency key missing"
	ErrInvalidIdempotencyKey = "invalid idempotency key"
	ErrRequestInProgress     = "request in progress"
)

type CapturedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type IdempotencyStorage interface {
	Get(ctx context.Context, key string) (*CapturedResponse, bool, error)
	Store(ctx context.Context, key string, resp *CapturedResponse) error

	AcquireLock(ctx context.Context, key string, ttl time.Duration) (string, error)
	ReleaseLock(ctx context.Context, key, token string) error
}

type MiddlewareConfig struct {
	Storage    IdempotencyStorage
	LockTTL    time.Duration
	ResultTTL  time.Duration
	RetryCount int
	RetryDelay time.Duration
}

type idempotencyMiddleware struct {
	config MiddlewareConfig
}

type responseCapturer struct {
	gin.ResponseWriter
	body   *bytes.Buffer
	status int
}

func NewMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	m := &idempotencyMiddleware{
		config: config,
	}
	return m.Handle
}

func (m *idempotencyMiddleware) Handle(c *gin.Context) {
	key := c.GetHeader(HeaderIdempotencyKey)
	if key == "" {
		m.sendErrorResponse(c, http.StatusBadRequest, ErrIdempotencyKeyMissing, "No \""+HeaderIdempotencyKey+"\"header provided")
		return
	}

	if len(key) > 255 {
		m.sendErrorResponse(c, http.StatusBadRequest, ErrInvalidIdempotencyKey, "idempotency key is too long")
		return
	}

	lockToken, err := m.config.Storage.AcquireLock(c.Request.Context(), key, m.config.LockTTL)
	if err != nil {
		m.sendErrorResponse(c, http.StatusConflict, ErrRequestInProgress, "Another request with same idempotency key is being processed")
		return
	}
	defer m.config.Storage.ReleaseLock(c.Request.Context(), key, lockToken)

	cached, ok, err := m.config.Storage.Get(c.Request.Context(), key)
	if err != nil {
		m.sendErrorResponse(c, http.StatusInternalServerError, restapi.ErrTypeInternal, "Failed to check cached response")
		return
	}

	if ok {
		m.writeCachedResponse(c, cached)
		return
	}

	if err := c.Err(); err != nil {
		return
	}
	capturer := &responseCapturer{
		ResponseWriter: c.Writer,
		body:           &bytes.Buffer{},
		status:         http.StatusOK,
	}
	c.Writer = capturer
	c.Next()

	resp := &CapturedResponse{
		StatusCode: capturer.status,
		Headers:    capturer.Header().Clone(),
		Body:       capturer.body.Bytes(),
	}

	if resp.StatusCode < 500 && resp.StatusCode != 429 {
		m.storeResponseWithRetry(c.Request.Context(), key, resp)
	}
}

func (r *responseCapturer) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func (r *responseCapturer) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (m *idempotencyMiddleware) storeResponseWithRetry(ctx context.Context, key string, resp *CapturedResponse) {
	var err error

	for i := 0; i < m.config.RetryCount; i++ {
		err = m.config.Storage.Store(ctx, key, resp)
		if err == nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(m.config.RetryDelay * time.Duration(i+1)):
			continue
		}
	}
}

func (m *idempotencyMiddleware) writeCachedResponse(c *gin.Context, cached *CapturedResponse) {
	for key, values := range cached.Headers {
		for _, value := range values {
			c.Writer.Header().Add(key, value)
		}
	}

	c.Status(cached.StatusCode)

	if _, err := c.Writer.Write(cached.Body); err != nil {
		for key := range cached.Headers {
			c.Writer.Header().Del(key)
		}
		m.sendErrorResponse(c, http.StatusInternalServerError, restapi.ErrTypeInternal, "Failed to write cached response")
		return
	}

	c.Abort()
}

func (m *idempotencyMiddleware) sendErrorResponse(c *gin.Context, status int, errorType, errorMessage string) {
	c.AbortWithStatusJSON(status, gin.H{
		"error_type": errorType,
		"message":    errorMessage,
	})
}
