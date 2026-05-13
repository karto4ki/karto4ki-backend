package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
)

type AchievementHandler struct {
	achievementSvc *services.AchievementService
}

func NewAchievementHandler(achievementSvc *services.AchievementService) *AchievementHandler {
	return &AchievementHandler{achievementSvc: achievementSvc}
}

func (h *AchievementHandler) GetMyAchievements(c *gin.Context) {
	userIDStr := c.GetString("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
		return
	}
	ach, err := h.achievementSvc.GetByUserID(c.Request.Context(), userID)
	if err != nil {
		if err == services.ErrNotFound {
			c.JSON(http.StatusOK, gin.H{"data": gin.H{"sets": 0, "streak": 0}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"sets":   ach.Sets,
			"streak": ach.Streak,
		},
	})
}
