package restapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

// UploadFileConfig - конфигурация для загрузки файла
type UploadFileConfig struct {
	MaxFileSize int64 `json:"max_file_size"` // Максимальный размер файла в байтах (по умолчанию 10MB)
}

// UploadFile - HTTP handler для загрузки файла целиком
func UploadFile(cfg *UploadFileConfig, svc *services.UploadFileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получаем файл из multipart form
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				ErrorType:    ErrTypeInvalidRequest,
				ErrorMessage: "Failed to get file from request",
			})
			return
		}
		defer file.Close()

		// Проверка размера файла
		if cfg.MaxFileSize > 0 && header.Size > cfg.MaxFileSize {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				ErrorType:    ErrTypeInvalidRequest,
				ErrorMessage: "File too large. Maximum size is 10MB",
			})
			return
		}

		// Читаем файл в память
		fileData := make([]byte, header.Size)
		if _, err := file.Read(fileData); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				ErrorType:    ErrTypeInternal,
				ErrorMessage: "Failed to read file",
			})
			return
		}

		// Получаем owner_id из контекста (JWT token)
		ownerIDStr := c.GetString("user_id")
		if ownerIDStr == "" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				ErrorType:    ErrTypeUnauthorized,
				ErrorMessage: "User ID not found in token",
			})
			return
		}

		// Определяем тип файла (avatar, document, etc.)
		fileType := c.DefaultPostForm("file_type", "other")

		// Загружаем файл через сервис
		resp, err := svc.UploadFile(c.Request.Context(), fileData, header.Filename, header.Header.Get("Content-Type"), fileType, ownerIDStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				ErrorType:    ErrTypeInternal,
				ErrorMessage: "Failed to upload file: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, UploadFileResponse{
			FileID:   resp.FileID,
			FileURL:  resp.FileURL,
			FileSize: resp.FileSize,
			MimeType: resp.MimeType,
		})
	}
}

// GetFile - HTTP handler для получения информации о файле
func GetFile(svc *services.FileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		fileIDStr := c.Param("file_id")
		fileID, err := uuid.Parse(fileIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				ErrorType:    ErrTypeInvalidRequest,
				ErrorMessage: "Invalid file_id format",
			})
			return
		}

		// Получаем информацию о файле
		fileMeta, found, err := svc.GetFileMeta(c.Request.Context(), fileID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				ErrorType:    ErrTypeInternal,
				ErrorMessage: "Failed to get file info",
			})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, ErrorResponse{
				ErrorType:    ErrTypeFileNotFound,
				ErrorMessage: "File not found",
			})
			return
		}

		c.JSON(http.StatusOK, FileInfoResponse{
			FileID:    fileMeta.FileID.String(),
			FileURL:   fileMeta.FileURL,
			OwnerID:   fileMeta.OwnerID,
			FileType:  fileMeta.FileType,
			FileSize:  fileMeta.FileSize,
			MimeType:  fileMeta.MimeType,
			CreatedAt: fileMeta.CreatedAt.Format(time.RFC3339),
		})
	}
}

// DeleteFile - HTTP handler для удаления файла
func DeleteFile(svc *services.FileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		fileIDStr := c.Param("file_id")
		fileID, err := uuid.Parse(fileIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				ErrorType:    ErrTypeInvalidRequest,
				ErrorMessage: "Invalid file_id format",
			})
			return
		}

		// Получаем owner_id из токена
		ownerIDStr := c.GetString("user_id")
		if ownerIDStr == "" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				ErrorType:    ErrTypeUnauthorized,
				ErrorMessage: "User ID not found in token",
			})
			return
		}

		// Проверяем, что пользователь владеет файлом
		fileMeta, found, err := svc.GetFileMeta(c.Request.Context(), fileID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				ErrorType:    ErrTypeInternal,
				ErrorMessage: "Failed to get file info",
			})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, ErrorResponse{
				ErrorType:    ErrTypeFileNotFound,
				ErrorMessage: "File not found",
			})
			return
		}

		if fileMeta.OwnerID != ownerIDStr {
			c.JSON(http.StatusForbidden, ErrorResponse{
				ErrorType:    ErrTypeForbidden,
				ErrorMessage: "You can only delete your own files",
			})
			return
		}

		// Удаляем файл
		if err := svc.DeleteFile(c.Request.Context(), fileID); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				ErrorType:    ErrTypeInternal,
				ErrorMessage: "Failed to delete file",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "File deleted"})
	}
}
