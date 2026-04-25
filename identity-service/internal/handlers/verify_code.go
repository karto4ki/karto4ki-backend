package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/restapi"
)

type VerifyCodeRequest struct {
	SignUpKey uuid.UUID `json:"signup_key" binding:"required"`
	Code      string    `json:"code" binding:"required,len=6"`
}

type SignUpVerifyCodeService interface {
	VerifyCode(ctx context.Context, signUpKey uuid.UUID, code string) error
}

func VerifyCode(service SignUpVerifyCodeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req VerifyCodeRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		err := service.VerifyCode(c.Request.Context(), req.SignUpKey, req.Code)
		if err != nil {
			switch err {
			case services.ErrAuthKeyNotFound:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeSignUpKeyNotFound,
					ErrorMessage: "Auth key doesn't exist",
				})
			case services.ErrWrongCode:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeWrongCode,
					ErrorMessage: "Wrong phone verification code",
				})
			default:
				c.Error(err)
				restapi.SendInternalError(c)
			}
			return
		}

		restapi.SendSuccess(c, signUpVerifyCodeResponse{})
	}
}

type signUpVerifyCodeResponse struct{}
