package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

type FileHandler struct {
	service *services.FileService
}

func NewFileHandler(service *services.FileService) *FileHandler {
	return &FileHandler{service: service}
}

func (h *FileHandler) UploadFile(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "invalid_request",
			"error_message": "Failed to get file from request",
		})
		return
	}
	defer file.Close()

	fileTypeStr := c.PostForm("type")
	if fileTypeStr == "" {
		fileTypeStr = "other"
	}

	var fileType models.FileType
	switch fileTypeStr {
	case "avatar":
		fileType = models.FileTypeAvatar
	case "card_image":
		fileType = models.FileTypeCardImage
	case "document":
		fileType = models.FileTypeDocument
	default:
		fileType = models.FileTypeOther
	}

	ownerID := c.GetString("user_id")

	response, err := h.service.Upload(c.Request.Context(), file, header.Filename, fileType, ownerID)
	if err != nil {
		if err.Error() == "file type not allowed" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_type":    "invalid_file_type",
				"error_message": err.Error(),
			})
			return
		}
		if err.Error() == "file size exceeds limit" {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error_type":    "file_too_large",
				"error_message": err.Error(),
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": response,
	})
}

func (h *FileHandler) GetFileInfo(c *gin.Context) {
	fileID := c.Param("fileId")

	fileInfo, err := h.service.GetFile(c.Request.Context(), fileID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "File not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": fileInfo,
	})
}

func (h *FileHandler) DeleteFile(c *gin.Context) {
	fileID := c.Param("fileId")

	if err := h.service.DeleteFile(c.Request.Context(), fileID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "File not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{},
	})
}

func (h *FileHandler) GetRawFile(c *gin.Context) {
	fileID := c.Param("fileId")

	mimeType, data, err := h.service.GetRawFile(c.Request.Context(), fileID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "File not found",
		})
		return
	}

	c.Data(http.StatusOK, mimeType, data)
}

func (h *FileHandler) ResizeImage(c *gin.Context) {
	imageID := c.Param("imageId")

	width := 800
	height := 800
	fit := "cover"

	if w := c.Query("width"); w != "" {
		if parsed, err := strconv.Atoi(w); err == nil && parsed > 0 {
			width = parsed
		}
	}

	if h := c.Query("height"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil && parsed > 0 {
			height = parsed
		}
	}

	if f := c.Query("fit"); f != "" {
		fit = f
	}

	mimeType, data, err := h.service.ResizeImage(c.Request.Context(), imageID, width, height, fit)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "Image not found",
		})
		return
	}

	c.Data(http.StatusOK, mimeType, data)
}

func (h *FileHandler) GetThumbnail(c *gin.Context) {
	imageID := c.Param("imageId")

	size := c.Query("size")
	if size == "" {
		size = "small"
	}

	mimeType, data, err := h.service.GetThumbnail(c.Request.Context(), imageID, size)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "Image not found",
		})
		return
	}

	c.Data(http.StatusOK, mimeType, data)
}
