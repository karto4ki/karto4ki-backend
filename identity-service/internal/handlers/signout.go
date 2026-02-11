package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
)

type SignOutService interface {
	SignOut(ctx context.Context, refreshToken string) error
}

type SignOutRequest struct {
	refreshToken string `json:"refresh_token"`
}

type SignOutResponse struct {
}

func SignOut(service SignOutService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SignOutRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
		}

		err := service.SignOut(c.Request.Context(), req.refreshToken)
		if err != nil && err != services.ErrRefreshTokenExpired {
			if err == services.ErrInvalidJWT {
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidJWT,
					ErrorMessage: "Refresh token is invalid",
				})
			}
			c.Error(err)
			restapi.SendInternalError(c)
		}

		restapi.SendSuccess(c, SignOutResponse{})
	}
}
