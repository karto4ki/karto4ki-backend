package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
)

type LearningHandler struct {
	service *services.LearningService
}

func NewLearningHandler(service *services.LearningService) *LearningHandler {
	return &LearningHandler{service: service}
}

type StartStudyRequest struct {
	SessionType models.SessionType `json:"session_type"`
	Limit       int32              `json:"limit"`
}

type SubmitAnswerRequest struct {
	CardID      string             `json:"card_id" binding:"required"`
	Rating      models.CardRating  `json:"rating" binding:"oneof=0 1"`
	TimeSpentMs int64              `json:"time_spent_ms"`
}

func (h *LearningHandler) StartStudySession(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")

	var req StartStudyRequest
	req.SessionType = models.SessionTypeReview
	req.Limit = 20

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	session, err := h.service.StartStudySession(c.Request.Context(), setID, userID, req.SessionType, req.Limit)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "No cards available for study"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": session})
}

func (h *LearningHandler) StartStudySessionAll(c *gin.Context) {
	userID := c.GetString("user_id")

	var req StartStudyRequest
	req.SessionType = models.SessionTypeReview
	req.Limit = 20

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	session, err := h.service.StartStudySessionAll(c.Request.Context(), userID, req.SessionType, req.Limit)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "No cards available for study"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": session})
}

func (h *LearningHandler) SubmitAnswer(c *gin.Context) {
	sessionID := c.Param("sessionId")
	userID := c.GetString("user_id")
	var req SubmitAnswerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	result, err := h.service.SubmitAnswer(c.Request.Context(), sessionID, req.CardID, userID, req.Rating, req.TimeSpentMs)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Session or card not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *LearningHandler) GetSetStatistics(c *gin.Context) {
	setID := c.Param("setId")

	stats, err := h.service.GetSetStatistics(c.Request.Context(), setID)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Set not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}

func (h *LearningHandler) GetUserStatistics(c *gin.Context) {
	userID := c.GetString("user_id")

	stats, err := h.service.GetUserStatistics(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}
