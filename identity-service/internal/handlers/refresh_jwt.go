package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/karto4ki/karto4ki-backend/shared/restapi"
)

type RefreshJWTService interface {
	Refresh(ctx context.Context, refresh jwt.Token) (jwt.Pair, error)
}

type refreshJWTRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type JWTPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
				return
			case services.ErrRefreshTokenInvalidated:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeRefreshTokenInvalidated,
					ErrorMessage: "Refresh token invalidated",
				})
				return
			case services.ErrInvalidJWT:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidJWT,
					ErrorMessage: "Invalid signature of jwt",
				})
				return
			case services.ErrInvalidTokenType:
				c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeInvalidTokenType,
					ErrorMessage: "Invalid jwt token type",
				})
				return
			default:
				c.Error(err)
				restapi.SendInternalError(c)
				return
			}
		}
		restapi.SendSuccess(c, JWTPairResponse{
			AccessToken:  string(pair.Access),
			RefreshToken: string(pair.Refresh),
		})
	}
}
