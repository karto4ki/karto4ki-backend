package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/restapi"
)

type SignOutService interface {
	SignOut(ctx context.Context, refreshToken string) error
}

type SignOutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type SignOutResponse struct {
}

func SignOut(service SignOutService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SignOutRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		err := service.SignOut(c.Request.Context(), req.RefreshToken)
		if err != nil && err != services.ErrRefreshTokenExpired {
			if err == services.ErrInvalidJWT {
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidJWT,
					ErrorMessage: "Refresh token is invalid",
				})
				return
			}
			c.Error(err)
			restapi.SendInternalError(c)
			return
		}

		restapi.SendSuccess(c, SignOutResponse{})
	}
}
