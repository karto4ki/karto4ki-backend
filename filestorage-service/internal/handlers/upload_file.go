package handlers

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

type UploadFileConfig struct {
	MaxFileSize int64 `json:"max_file_size"`
}

func UploadFile(cfg *UploadFileConfig, svc *services.UploadFileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_type":    "INVALID_REQUEST",
				"error_message": "Failed to get file from request",
			})
			return
		}
		defer file.Close()

		if cfg.MaxFileSize > 0 && header.Size > cfg.MaxFileSize {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_type":    "INVALID_REQUEST",
				"error_message": "File too large. Maximum size is 10MB",
			})
			return
		}

		fileData, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_type":    "INTERNAL_ERROR",
				"error_message": "Failed to read file",
			})
			return
		}

		ownerIDStr := c.GetString("user_id")
		if ownerIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error_type":    "UNAUTHORIZED",
				"error_message": "User ID not found in token",
			})
			return
		}

		fileType := c.DefaultPostForm("file_type", "other")

		resp, err := svc.UploadFile(c.Request.Context(), fileData, header.Filename, header.Header.Get("Content-Type"), fileType, ownerIDStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_type":    "INTERNAL_ERROR",
				"error_message": "Failed to upload file: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"file_id":   resp.FileID,
				"file_url":  resp.FileURL,
				"file_size": resp.FileSize,
				"mime_type": resp.MimeType,
			},
		})
	}
}
