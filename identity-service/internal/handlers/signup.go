package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
)

type SignUpRequest struct {
	SignUpKey uuid.UUID `json:"signup_key" binding:"required"`
	Name      string    `json:"name" binding:"required"`
	Username  string    `json:"username" binding:"required"`
}

type SignUpResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func SignUp(service *services.SignUpService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SignUpRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}
		if req.SignUpKey == uuid.Nil {
			restapi.SendValidationError(c, []restapi.ErrorDetail{
				{
					Field:   "signup_key",
					Message: "should not be null",
				},
			})
			return
		}

		pair, err := service.SignUp(c.Request.Context(), req.SignUpKey, req.Name, req.Username)
		if err != nil {
			switch err {
			case services.ErrAuthKeyNotFound:
				c.JSON(http.StatusNotFound, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeSignUpKeyNotFound,
					ErrorMessage: "Signup key not found or expired",
				})
			case services.ErrCreateUserFailed:
				c.JSON(http.StatusInternalServerError, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInternal,
					ErrorMessage: "Failed to create user",
				})
			case services.ErrUserAlreadyExists:
				c.JSON(http.StatusConflict, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeUserAlreadyExists,
					ErrorMessage: "User already exists",
				})
			default:
				c.Error(err)
				restapi.SendInternalError(c)
			}
			return
		}

		restapi.SendSuccess(c, SignUpResponse{
			AccessToken:  string(pair.Access),
			RefreshToken: string(pair.Refresh),
		})
	}
}
