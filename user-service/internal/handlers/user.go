package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
)

type UserHandler struct {
	userSvc *services.UserService
}

func NewUserHandler(userSvc *services.UserService) *UserHandler {
	return &UserHandler{userSvc: userSvc}
}

func (h *UserHandler) CheckUsername(c *gin.Context) {
	username := c.Param("username")
	exists, err := h.userSvc.ExistsByUsername(c.Request.Context(), username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"user_exists": exists}})
}

func (h *UserHandler) GetPublicProfile(c *gin.Context) {
	username := c.Param("username")
	user, err := h.userSvc.GetUserByUsername(c.Request.Context(), username)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": mapToPublic(user)})
}

func (h *UserHandler) SearchUsers(c *gin.Context) {
	name := c.Query("name")
	username := c.Query("username")
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	req := storage.SearchUsersRequest{
		Name:     nil,
		Username: nil,
		Offset:   offset,
		Limit:    limit,
	}
	if name != "" {
		req.Name = &name
	}
	if username != "" {
		req.Username = &username
	}
	if req.Name == nil && req.Username == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one search criteria (name or username) is required"})
		return
	}

	resp, err := h.userSvc.SearchUsers(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"users":  mapToPublicList(resp.Users),
			"offset": resp.Offset,
			"count":  resp.Count,
		},
	})
}

func mapToPublic(user *models.User) map[string]interface{} {
	return gin.H{
		"id":         user.ID.String(),
		"name":       user.Name,
		"username":   user.Username,
		"photo":      user.PhotoURL,
		"created_at": user.CreatedAt.Format(time.RFC3339),
	}
}

func mapToPublicList(users []models.User) []map[string]interface{} {
	result := make([]map[string]interface{}, len(users))
	for i, u := range users {
		result[i] = mapToPublic(&u)
	}
	return result
}
