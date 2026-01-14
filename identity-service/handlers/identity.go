package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/services"
)

const (
	HeaderAuthorization = "Authorization"
	HeaderInternalToken = "X-Internal-Token"
)

type AuthService interface {
	Authenticate(ctx context.Context, token jwt.Token) (jwt.Token, error)
}

func NewIdentityHandler(service AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(HeaderAuthorization)
		if authHeader == "" {
			respondUnauthorized(c, "Authorization header is required")
			return
		}

		accessToken, ok := extractBearerToken(authHeader)
		if !ok {
			respondUnauthorized(c, "Invalid Authorization header format. Expected: Bearer <token>")
			return
		}

		internalToken, err := service.Authenticate(c.Request.Context(), accessToken)
		if err != nil {
			handleAuthError(c, err)
			return
		}

		c.Header(HeaderInternalToken, string(internalToken))

		c.Next()
	}
}

func extractBearerToken(authHeader string) (jwt.Token, bool) {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", false
	}

	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return "", false
	}

	return jwt.Token(token), true
}

func respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, restapi.ErrorResponse{
		ErrorType:    restapi.ErrTypeUnautorized,
		ErrorMessage: message,
	})
	c.Abort()
}

func handleAuthError(c *gin.Context, err error) {
	switch err {
	case services.ErrInvalidJWT:
		c.JSON(http.StatusUnauthorized, restapi.ErrorResponse{
			ErrorType:    restapi.ErrTypeInvalidJWT,
			ErrorMessage: "Invalid or malformed JWT token",
		})
	case services.ErrTypeAccessTokenExpired:
		c.JSON(http.StatusUnauthorized, restapi.ErrorResponse{
			ErrorType:    restapi.ErrTypeAccessTokenExpired,
			ErrorMessage: "Access token has expired",
		})
	case services.ErrInvalidTokenType:
		c.JSON(http.StatusUnauthorized, restapi.ErrorResponse{
			ErrorType:    restapi.ErrTypeInvalidTokenType,
			ErrorMessage: "Invalid token type. Expected access token",
		})
	default:
		c.Error(err)
		restapi.SendInternalError(c)
	}
	c.Abort()
}

func getInternalToken(c *gin.Context) (string, bool) {
	token := c.GetHeader(HeaderInternalToken)
	if token == "" {
		return "", false
	}
	return token, true
}

func GetInternalToken(c *gin.Context) string {
	token, ok := getInternalToken(c)
	if !ok {
		panic("internal token not found in request context")
	}
	return token
}
