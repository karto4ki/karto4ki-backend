package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
)

type ProfileHandler struct {
	userSvc       *services.UserService
	fileStorageURL string
}

func NewProfileHandler(userSvc *services.UserService, fileStorageURL string) *ProfileHandler {
	return &ProfileHandler{userSvc: userSvc, fileStorageURL: fileStorageURL}
}

func (h *ProfileHandler) GetMyProfile(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id in token"})
		return
	}
	user, err := h.userSvc.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": mapToPrivate(user)})
}

type UpdateProfileRequest struct {
	Name                string `json:"name" binding:"required"`
	Username            string `json:"username" binding:"required"`
	NotificationEnabled bool   `json:"notification_enabled" binding:"required"`
}

func (h *ProfileHandler) UpdateMyProfile(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
		return
	}
	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	updated, err := h.userSvc.UpdateUser(c.Request.Context(), userID, req.Name, req.Username, req.NotificationEnabled)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if err == services.ErrAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": mapToPrivate(updated)})
}

func (h *ProfileHandler) DeleteMyProfile(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
		return
	}
	err = h.userSvc.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{}})
}

type UpdatePhotoRequest struct {
	PhotoID string `json:"photo_id" binding:"required"`
}

func (h *ProfileHandler) UpdateProfilePhoto(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
		return
	}
	var req UpdatePhotoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	photoURL := h.fileStorageURL + "/api/storage/v1.0/files/" + req.PhotoID + "/raw"
	updated, err := h.userSvc.UpdatePhoto(c.Request.Context(), userID, photoURL)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": mapToPrivate(updated)})
}

func (h *ProfileHandler) UploadProfilePhoto(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error_type": "unauthorized", "error_message": "invalid user id"})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "invalid_request", "error_message": "Failed to get file"})
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", header.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to create form"})
		return
	}

	if _, err := io.Copy(part, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to copy file"})
		return
	}

	fieldWriter, err := writer.CreateFormField("type")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to create field"})
		return
	}
	if _, err := fieldWriter.Write([]byte("avatar")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to write field"})
		return
	}

	if err := writer.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to close writer"})
		return
	}

	req, err := http.NewRequest("POST", h.fileStorageURL+"/api/storage/v1.0/upload", body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to upload file"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(resp.StatusCode, gin.H{"error_type": "upload_failed", "error_message": "Failed to upload file to storage"})
		return
	}

	var uploadResp struct {
		Data struct {
			FileID  string `json:"file_id"`
			FileURL string `json:"file_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to parse response"})
		return
	}

	photoURL := h.fileStorageURL + uploadResp.Data.FileURL
	updated, err := h.userSvc.UpdatePhoto(c.Request.Context(), userID, photoURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": mapToPrivate(updated)})
}

func (h *ProfileHandler) DeleteProfilePhoto(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
		return
	}
	updated, err := h.userSvc.DeletePhoto(c.Request.Context(), userID)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": mapToPrivate(updated)})
}

func mapToPrivate(user *models.User) map[string]interface{} {
	data := gin.H{
		"id":                   user.ID.String(),
		"name":                 user.Name,
		"username":             user.Username,
		"photo":                user.PhotoURL,
		"created_at":           user.CreatedAt.Format(time.RFC3339),
		"notification_enabled": user.NotificationEnabled,
	}
	if user.Email != nil {
		data["email"] = *user.Email
	} else {
		data["email"] = nil
	}
	return data
}
