package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
)

func ActivityTrackingMiddleware(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.Next()
			return
		}

		id, err := uuid.Parse(userID)
		if err != nil {
			c.Next()
			return
		}

		go func() {
			if err := userService.UpdateLastActivity(c.Request.Context(), id); err != nil {
			}
		}()

		c.Next()
	}
}

func UpdateActivityHandler(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error_type":    "unauthorized",
				"error_message": "User ID not found",
			})
			return
		}

		id, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_type":    "validation_failed",
				"error_message": "Invalid user ID",
			})
			return
		}

		if err := userService.UpdateLastActivity(c.Request.Context(), id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_type":    "internal",
				"error_message": "Failed to update activity: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"message": "Activity updated",
			},
		})
	}
}
