package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
)

// PushHandler handles push notification related requests
type PushHandler struct {
	pushService *services.PushService
	userService *services.UserService
}

// NewPushHandler creates a new push handler
func NewPushHandler(pushService *services.PushService, userService *services.UserService) *PushHandler {
	return &PushHandler{
		pushService: pushService,
		userService: userService,
	}
}

// RegisterDeviceRequest represents a request to register a device token
type RegisterDeviceRequest struct {
	DeviceType string `json:"device_type" binding:"required,oneof=ios"`
	Token      string `json:"token" binding:"required"`
	AppVersion string `json:"app_version"`
}

// RegisterDevice registers a device token for push notifications
func (h *PushHandler) RegisterDevice(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid user ID format",
		})
		return
	}

	var req RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid request body",
			"error_details": []gin.H{{"field": "body", "message": err.Error()}},
		})
		return
	}

	// Validate device token format
	if !services.ValidateDeviceToken(req.Token, services.DeviceType(req.DeviceType)) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid device token format",
			"error_details": []gin.H{{"field": "token", "message": "Token must be valid " + req.DeviceType + " device token"}},
		})
		return
	}

	// Save device token
	if err := h.userService.SaveDeviceToken(c.Request.Context(), userUUID, req.DeviceType, req.Token, req.AppVersion); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to register device: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Device registered successfully",
		},
	})
}

// UnregisterDevice removes a device token
func (h *PushHandler) UnregisterDevice(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid user ID format",
		})
		return
	}

	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid request body",
		})
		return
	}

	if err := h.userService.DeleteDeviceToken(c.Request.Context(), userUUID, req.Token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to unregister device: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Device unregistered successfully",
		},
	})
}

// GetDevices returns all registered devices for the user
func (h *PushHandler) GetDevices(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid user ID format",
		})
		return
	}

	tokens, err := h.userService.GetDeviceTokens(c.Request.Context(), userUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to get devices: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"devices": tokens,
		},
	})
}

// TestPushRequest represents a test push notification request
type TestPushRequest struct {
	Title string `json:"title" binding:"required"`
	Body  string `json:"body" binding:"required"`
}

// TestPush sends a test push notification
func (h *PushHandler) TestPush(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid user ID format",
		})
		return
	}

	var req TestPushRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid request body",
		})
		return
	}

	// Get user's devices
	tokens, err := h.userService.GetDeviceTokens(c.Request.Context(), userUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to get devices: " + err.Error(),
		})
		return
	}

	if len(tokens) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "no_devices",
			"error_message": "No devices registered for this user",
		})
		return
	}

	// Send test push to first device
	device := tokens[0]
	result, err := h.pushService.Send(c.Request.Context(), &services.PushNotification{
		UserID:      userID,
		DeviceToken: device.Token,
		DeviceType:  services.DeviceiOS,
		Title:       req.Title,
		Body:        req.Body,
		Data: map[string]interface{}{
			"type":      "test",
			"timestamp": device.Token,
		},
		Sound: "default",
	})

	if err != nil || !result.Success {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "push_failed",
			"error_message": "Failed to send test push: " + result.Error,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message":    "Test push sent successfully",
			"device":     device.DeviceType,
			"message_id": result.MessageID,
		},
	})
}
