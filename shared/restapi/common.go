package restapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SendSuccess(c *gin.Context, data any) {
	c.JSON(http.StatusOK, SuccessResponse{
		Data: data,
	})
}

func SendUnprocessableJSON(c *gin.Context) {
	c.JSON(http.StatusUnprocessableEntity, ErrorResponse{
		ErrorType:    ErrTypeInvalidJson,
		ErrorMessage: "Body has invalid JSON",
	})
}

func SendValidationError(c *gin.Context, errors []ErrorDetail) {
	c.JSON(http.StatusBadRequest, ErrorResponse{
		ErrorType:    ErrTypeValidationFailed,
		ErrorMessage: "Validation has failed",
		ErrorDetails: errors,
	})
}

func SendUnautorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, ErrorResponse{
		ErrorType:    ErrTypeUnautorized,
		ErrorMessage: "Unauthorized",
	})
}

func SendInternalError(c *gin.Context) {
	errResp := ErrorResponse{
		ErrorType:    ErrTypeInternal,
		ErrorMessage: "Internal Server Error",
	}
	c.JSON(http.StatusInternalServerError, errResp)
}
