package handlers

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

type UploadInitService interface {
	Init(context.Context, *services.UploadInitRequest) (uuid.UUID, error)
}

func UploadInit(service UploadInitService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req uploadInitRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		uploadID, err := service.Init(c.Request.Context(), &services.UploadInitRequest{
			FileName: req.FileName,
			MimeType: req.MimeType,
		})
		if err != nil {
			c.Error(err)
			restapi.SendInternalError(c)
			return
		}

		restapi.SendSuccess(c, UploadInitResponse{
			UploadID: uploadID,
		})
	}
}

type uploadInitRequest struct {
	FileName string `json:"file_name" binding:"required"`
	MimeType string `json:"mime_type" binding:"required"`
}

type UploadInitResponse struct {
	UploadID uuid.UUID `json:"upload_id"`
}
