package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/services"
)

type SignInService interface {
	SignIn(ctx context.Context, signinKey uuid.UUID, code string) (jwt.Pair, error)
}

type SignInRequest struct {
	SignInKey uuid.UUID `json:"signin_key", binding:"required"`
	Code      string    `json:"code"`
}

type SignInResponse struct {
}

func SignIn(service SignInService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SignInRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}
		if req.SignInKey == uuid.Nil {
			restapi.SendValidationError(c, []restapi.ErrorDetail{
				{
					Field:   "signin_key",
					Message: "shouldn't be nil",
				},
			})
		}

		pair, err := service.SignIn(c.Request.Context(), req.SignInKey, req.Code)
		if err != nil {
			switch err {
			case services.ErrSignInKeyNotFound:
				c.JSON(http.StatusNotFound, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeSignInKeyNotFound,
					ErrorMessage: "Sign in key was not found",
				})
			case services.ErrWrongCode:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeWrongCode,
					ErrorMessage: "Wrong email verification code",
				})
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
