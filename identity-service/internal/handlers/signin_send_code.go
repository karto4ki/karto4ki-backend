package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
)

type SendCodeRequest struct {
	Email string `json:"email"`
}

type SendCodeResponse struct {
	SignInKey uuid.UUID `json:"signin_key"`
}

type SigninSendCodeService interface {
	SignInSendCode(ctx context.Context, email string) (signinKey uuid.UUID, err error)
}

func SignInSendCode(service SigninSendCodeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SendCodeRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		signInKey, err := service.SignInSendCode(c.Request.Context(), req.Email)

		if err != nil {
			switch err {
			case services.ErrUserNotFound:
				c.JSON(http.StatusNotFound, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeUserNotFound,
					ErrorMessage: "Such user doesn't exist",
				})
			case services.ErrSendCodeFreqExceeded:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeSendCodeFreqExceeded,
					ErrorMessage: "Send code operation frequency exceeded",
				})
			case services.ErrFindSignInMetaFail:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType: restapi.ErrTypeSignInMetaFail,
				})
			default:
				c.Error(err)
				restapi.SendInternalError(c)
			}
			return
		}

		restapi.SendSuccess(c, SendCodeResponse{
			SignInKey: signInKey,
		})
	}
}
