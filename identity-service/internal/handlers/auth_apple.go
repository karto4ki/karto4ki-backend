package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/karto4ki/karto4ki-backend/shared/restapi"
)

type appleAuthRequest struct {
	IDToken string                  `json:"id_token" binding:"required"`
	User    *services.AppleUserData `json:"user,omitempty"`
}

type AppleAuthService interface {
	Authenticate(ctx context.Context, idToken string, userData *services.AppleUserData) (jwt.Pair, error)
}

func AppleAuth(service AppleAuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req appleAuthRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		pair, err := service.Authenticate(c.Request.Context(), req.IDToken, req.User)
		if err != nil {
			switch {
			case errors.Is(err, services.ErrInvalidAppleToken):
				c.JSON(http.StatusUnauthorized, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidAppleToken,
					ErrorMessage: "Invalid Apple ID token",
				})
			case errors.Is(err, services.ErrProviderAlreadyLinked):
				c.JSON(http.StatusConflict, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeProviderAlreadyLinked,
					ErrorMessage: "This Apple account is already linked to another user",
				})
			case errors.Is(err, services.ErrUserServiceUnavailable),
				errors.Is(err, services.ErrUserCreationFailed),
				errors.Is(err, services.ErrUnexpectedUserServiceStatus):
				c.Error(err)
				restapi.SendInternalError(c)
			default:
				c.Error(err)
				restapi.SendInternalError(c)
			}
			return
		}

		restapi.SendSuccess(c, JWTPairResponse{
			AccessToken:  string(pair.Access),
			RefreshToken: string(pair.Refresh),
		})
	}
}
