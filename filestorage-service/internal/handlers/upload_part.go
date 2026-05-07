package handlers

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/filestorage-service/internal/services"
)

const (
	fieldPartNumber = "part_number"
	fieldUploadID   = "upload_id"
	fieldPart       = "part"
)

type UploadPartService interface {
	UploadPart(context.Context, *services.UploadPartRequest) (*services.UploadPartResponse, error)
}

type MultipartUploadConfig struct {
	MaxPartSize int64
}

func UploadPart(conf *MultipartUploadConfig, service UploadPartService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.Request.ParseMultipartForm(conf.MaxPartSize); err != nil {
			if err == multipart.ErrMessageTooLarge {
				c.JSON(http.StatusRequestEntityTooLarge, restapi.ErrorResponse{
					ErrorType:    restapi.ErrTypeContentTooLarge,
					ErrorMessage: fmt.Sprintf("Content is too large. It must be not greater than %d bytes", conf.MaxPartSize),
				})
				return
			}
			c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
				ErrorType:    restapi.ErrTypeInvalidForm,
				ErrorMessage: "Can't parse multipart form",
			})
			return
		}

		partNumber, err := strconv.Atoi(c.Request.FormValue(fieldPartNumber))
		if err != nil {
			restapi.SendValidationError(c, []restapi.ErrorDetail{{
				Field:   fieldPartNumber,
				Message: "Part number is missing or invalid",
			}})
			return
		}

		uploadID, err := uuid.Parse(c.Request.FormValue(fieldUploadID))
		if err != nil {
			restapi.SendValidationError(c, []restapi.ErrorDetail{{
				Field:   fieldUploadID,
				Message: "Upload ID is missing or invalid",
			}})
			return
		}

		filePart, _, err := c.Request.FormFile(fieldPart)
		if err != nil {
			c.JSON(http.StatusBadRequest, restapi.ErrorResponse{
				ErrorType:    restapi.ErrTypeInvalidForm,
				ErrorMessage: "Can't parse form file",
			})
			return
		}
		defer filePart.Close()

		resp, err := service.UploadPart(c.Request.Context(), &services.UploadPartRequest{
			PartNumber: partNumber,
			UploadID:   uploadID,
			Part:       filePart,
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

		restapi.SendSuccess(c, UploadPartResponse{
			ETag: resp.ETag,
		})
	}
}

type UploadPartResponse struct {
	ETag string `json:"e_tag"`
}
