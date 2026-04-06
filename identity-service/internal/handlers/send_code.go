package handlers

import (
	"context"
	"log"
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
	IsExisted bool      `json:"is_existed"`
}

type SigninSendCodeService interface {
	SignInSendCode(ctx context.Context, email string) (signinKey uuid.UUID, isExist bool, err error)
}

func SignInSendCode(service SigninSendCodeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SendCodeRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		signInKey, isExist, err := service.SignInSendCode(c.Request.Context(), req.Email)

		if err != nil {
			switch err {
			case services.ErrSendCodeFreqExceeded:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeSendCodeFreqExceeded,
					ErrorMessage: "Send code operation frequency exceeded",
				})
				return
			case services.ErrFindSignInMetaFail:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType: restapi.ErrTypeSignInMetaFail,
				})
				return
			default:
				log.Printf("default: %s", err)
				c.Error(err)
				restapi.SendInternalError(c)
				return
			}
		}

		restapi.SendSuccess(c, SendCodeResponse{
			SignInKey: signInKey,
			IsExisted: isExist,
		})
	}
}
