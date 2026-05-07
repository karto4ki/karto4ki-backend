package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/restapi"
)

var ErrUploadNotFound = errors.New("upload not found")

type UploadAbortService interface {
	Abort(ctx context.Context, uploadID uuid.UUID) error
}

func UploadAbort(service UploadAbortService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req uploadAbortRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		err := service.Abort(c.Request.Context(), req.UploadID)
		if err != nil {
			if err == ErrUploadNotFound {
				c.JSON(http.StatusNotFound, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeUploadNotFound,
					ErrorMessage: "Upload not found",
				})
				return
			}
			c.Error(err)
			restapi.SendInternalError(c)
			return
		}

		restapi.SendSuccess(c, struct{}{})
	}
}

type uploadAbortRequest struct {
	UploadID uuid.UUID `json:"upload_id" binding:"required"`
}
