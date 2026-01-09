package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/services"
)

type RefreshJWTService interface {
	Refresh(ctx context.Context, refresh jwt.Token) (jwt.Pair, error)
}

type refreshJWTRequest struct {
	RefreshToken string `json: "refresh_token"`
}

type refreshJWTResponse struct {
	AccessToken  string `json: "access_token"`
	RefreshToken string `json: "refresh_token"`
}

func RefreshJWT(service RefreshJWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshJWTRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}
		pair, err := service.Refresh(c.Request.Context(), jwt.Token(req.RefreshToken))
		if err != nil {
			switch err {
			case services.ErrRefreshTokenExpired:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeRefreshTokenExpired,
					ErrorMessage: "Refresh token expired",
				})
			case services.ErrRefreshTokenInvalidated:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeRefreshTokenInvalidated,
					ErrorMessage: "Refresh token invalidated",
				})
			case services.ErrInvalidJWT:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidJWT,
					ErrorMessage: "Invalid signature of jwt",
				})
			case services.ErrInvalidTokenType:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidTokenType,
					ErrorMessage: "Invalid jwt token type",
				})
			default:
				c.Error(err)
				restapi.SendInternalError(c)
			}
		}
		restapi.SendSuccess(c, refreshJWTResponse{
			AccessToken:  string(pair.Access),
			RefreshToken: string(pair.Refresh),
		})
	}
}
