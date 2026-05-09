package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

func GetFile(svc *services.FileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		fileIDStr := c.Param("file_id")
		fileID, err := uuid.Parse(fileIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_type":    "INVALID_REQUEST",
				"error_message": "Invalid file_id format",
			})
			return
		}

		fileMeta, found, err := svc.GetFileMeta(c.Request.Context(), fileID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_type":    "INTERNAL_ERROR",
				"error_message": "Failed to get file info",
			})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{
				"error_type":    "FILE_NOT_FOUND",
				"error_message": "File not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"file_id":    fileMeta.FileID.String(),
			"file_url":   fileMeta.FileURL,
			"owner_id":   fileMeta.OwnerID,
			"file_type":  fileMeta.FileType,
			"file_size":  fileMeta.FileSize,
			"mime_type":  fileMeta.MimeType,
			"created_at": fileMeta.CreatedAt.Format(time.RFC3339),
		})
	}
}
