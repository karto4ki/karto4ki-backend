package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

func DeleteFile(svc *services.FileService) gin.HandlerFunc {
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

		ownerIDStr := c.GetString("user_id")
		if ownerIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error_type":    "UNAUTHORIZED",
				"error_message": "User ID not found in token",
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

		if fileMeta.OwnerID != ownerIDStr {
			c.JSON(http.StatusForbidden, gin.H{
				"error_type":    "FORBIDDEN",
				"error_message": "You can only delete your own files",
			})
			return
		}

		if err := svc.DeleteFile(c.Request.Context(), fileID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_type":    "INTERNAL_ERROR",
				"error_message": "Failed to delete file",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "File deleted"})
	}
}
