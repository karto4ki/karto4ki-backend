package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
)

type AIHandler struct {
	service *services.AIService
}

func NewAIHandler(service *services.AIService) *AIHandler {
	return &AIHandler{service: service}
}

type GenerateCardsRequest struct {
	Text           string `json:"text" binding:"required"`
	CardCount      int    `json:"card_count"`
	Difficulty     string `json:"difficulty"`
	Language       string `json:"language"`
	SetName        string `json:"set_name"`
	SetDescription string `json:"set_description"`
}

func (h *AIHandler) GenerateCards(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	internalToken := c.GetHeader("X-Internal-Token")
	if internalToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "Internal token not found",
		})
		return
	}

	var req GenerateCardsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid request body",
			"error_details": []gin.H{{"field": "body", "message": err.Error()}},
		})
		return
	}

	if req.Text == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Text is required",
			"error_details": []gin.H{{"field": "text", "message": "text field is required"}},
		})
		return
	}

	resp, err := h.service.GenerateCards(c.Request.Context(), userID, internalToken, services.GenerateCardsRequest{
		Text:           req.Text,
		CardCount:      req.CardCount,
		Difficulty:     req.Difficulty,
		Language:       req.Language,
		SetName:        req.SetName,
		SetDescription: req.SetDescription,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to generate cards: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": resp,
	})
}

func (h *AIHandler) GenerateQuiz(c *gin.Context) {
	var req services.GenerateQuizRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid request body",
			"error_details": []gin.H{{"field": "body", "message": err.Error()}},
		})
		return
	}

	if req.Text == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Text is required",
			"error_details": []gin.H{{"field": "text", "message": "text field is required"}},
		})
		return
	}

	resp, err := h.service.GenerateQuiz(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to generate quiz: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": resp,
	})
}

func (h *AIHandler) Summarize(c *gin.Context) {
	var req services.SummarizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid request body",
			"error_details": []gin.H{{"field": "body", "message": err.Error()}},
		})
		return
	}

	if req.Text == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Text is required",
			"error_details": []gin.H{{"field": "text", "message": "text field is required"}},
		})
		return
	}

	resp, err := h.service.Summarize(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to summarize: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": resp,
	})
}
