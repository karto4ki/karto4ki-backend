package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

type UploadCompleteService interface {
	Complete(context.Context, *services.UploadCompleteRequest) (*models.FileMeta, error)
}

func UploadComplete(service UploadCompleteService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req uploadCompleteRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			restapi.SendUnprocessableJSON(c)
			return
		}

		parts := make([]services.UploadPart, 0, len(req.Parts))
		for _, part := range req.Parts {
			parts = append(parts, services.UploadPart{
				PartNumber: part.PartNumber,
				ETag:       part.ETag,
			})
		}

		file, err := service.Complete(c.Request.Context(), &services.UploadCompleteRequest{
			UploadID: req.UploadID,
			Parts:    parts,
		})
		if err != nil {
			if err == services.ErrUploadNotFound {
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

		restapi.SendSuccess(c, fileResponse{
			FileName:  file.FileName,
			FileSize:  file.FileSize,
			MimeType:  file.MimeType,
			FileID:    file.FileID.String(),
			FileURL:   file.FileURL,
			CreatedAt: file.CreatedAt.Unix(),
		})
	}
}

type uploadCompleteRequest struct {
	UploadID uuid.UUID `json:"upload_id" binding:"required"`
	Parts    []struct {
		PartNumber int    `json:"part_number" binding:"required"`
		ETag       string `json:"e_tag" binding:"required"`
	} `json:"parts" binding:"required"`
}

type fileResponse struct {
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	MimeType  string `json:"mime_type"`
	FileID    string `json:"file_id"`
	FileURL   string `json:"file_url"`
	CreatedAt int64  `json:"created_at"`
}
