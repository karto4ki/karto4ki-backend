package handlers

import (
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

func GetRawFile(svc *services.FileService, s3Client *s3.Client, bucket string) gin.HandlerFunc {
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

		obj, err := s3Client.GetObject(c.Request.Context(), &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(fileID.String()),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_type":    "INTERNAL_ERROR",
				"error_message": "Failed to retrieve file",
			})
			return
		}
		defer obj.Body.Close()

		c.Header("Cache-Control", "public, max-age=86400")
		c.Header("Content-Type", fileMeta.MimeType)
		c.Status(http.StatusOK)
		io.Copy(c.Writer, obj.Body)
	}
}
