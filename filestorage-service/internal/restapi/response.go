package restapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ErrTypeInvalidForm      = "INVALID_FORM"
	ErrTypeContentTooLarge  = "CONTENT_TOO_LARGE"
	ErrTypeUploadNotFound   = "UPLOAD_NOT_FOUND"
	ErrTypeFileNotFound     = "FILE_NOT_FOUND"
	ErrTypeInternal         = "INTERNAL_ERROR"
	ErrTypeInvalidRequest   = "INVALID_REQUEST"
	ErrTypeUnauthorized     = "UNAUTHORIZED"
	ErrTypeForbidden        = "FORBIDDEN"
)

type ErrorResponse struct {
	ErrorType    string        `json:"error_type"`
	ErrorMessage string        `json:"error_message"`
	ErrorDetails []ErrorDetail `json:"error_details,omitempty"`
}

type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type SuccessResponse struct {
	Data interface{} `json:"data"`
}

type UploadFileResponse struct {
	FileID   string `json:"file_id"`
	FileURL  string `json:"file_url"`
	FileSize int64  `json:"file_size"`
	MimeType string `json:"mime_type"`
}

type FileInfoResponse struct {
	FileID    string `json:"file_id"`
	FileURL   string `json:"file_url"`
	OwnerID   string `json:"owner_id"`
	FileType  string `json:"file_type"`
	FileSize  int64  `json:"file_size"`
	MimeType  string `json:"mime_type"`
	CreatedAt string `json:"created_at"`
}

func SendSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, SuccessResponse{Data: data})
}

func SendInternalError(c *gin.Context) {
	c.JSON(http.StatusInternalServerError, ErrorResponse{
		ErrorType:    ErrTypeInternal,
		ErrorMessage: "Internal server error",
	})
}

func SendUnprocessableJSON(c *gin.Context) {
	c.JSON(http.StatusUnprocessableEntity, ErrorResponse{
		ErrorType:    ErrTypeInvalidForm,
		ErrorMessage: "Invalid request body",
	})
}

func SendValidationError(c *gin.Context, details []ErrorDetail) {
	c.JSON(http.StatusBadRequest, ErrorResponse{
		ErrorType:    ErrTypeInvalidForm,
		ErrorMessage: "Validation failed",
		ErrorDetails: details,
	})
}
