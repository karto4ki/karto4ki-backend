package handlers

import (
	"fmt"
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

	if req.CardCount < 1 || req.CardCount > 150 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid card count",
			"error_details": []gin.H{{"field": "card_count", "message": "card_count must be between 1 and 150"}},
		})
		return
	}

	// Use async generation with progress tracking
	taskID, err := h.service.GenerateCardsAsync(c.Request.Context(), userID, services.GenerateCardsRequest{
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
			"error_message": "Failed to start generation task: " + err.Error(),
		})
		return
	}

	// Return task ID for status polling
	c.JSON(http.StatusAccepted, gin.H{
		"data": gin.H{
			"task_id": taskID,
			"status":  "pending",
		},
	})
}

func (h *AIHandler) GenerateQuiz(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

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

	if req.QuestionCount < 1 || req.QuestionCount > 150 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid question count",
			"error_details": []gin.H{{"field": "question_count", "message": "question_count must be between 1 and 150"}},
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
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

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

// GenerateCardsFromImage handles image upload and card generation
func (h *AIHandler) GenerateCardsFromImage(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	// Parse multipart form (max 10MB)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10*1024*1024)
	if err := c.Request.ParseMultipartForm(10 * 1024 * 1024); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "File too large (max 10MB)",
			"error_details": []gin.H{{"field": "file", "message": err.Error()}},
		})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Image file is required",
			"error_details": []gin.H{{"field": "file", "message": err.Error()}},
		})
		return
	}
	defer file.Close()

	// Validate file type
	contentType := header.Header.Get("Content-Type")
	allowedTypes := map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/webp": true,
	}
	if !allowedTypes[contentType] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid file type. Allowed: JPEG, PNG, WebP",
			"error_details": []gin.H{{"field": "file", "message": fmt.Sprintf("got %s", contentType)}},
		})
		return
	}

	// Read image data
	imageData := make([]byte, header.Size)
	if _, err := file.Read(imageData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to read image",
			"error_details": []gin.H{{"field": "file", "message": err.Error()}},
		})
		return
	}

	// Parse optional form fields
	cardCount := 5
	if val := c.PostForm("card_count"); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &cardCount); err == nil && n == 1 {
			if cardCount < 1 || cardCount > 150 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error_type":    "validation_failed",
					"error_message": "Invalid card count",
					"error_details": []gin.H{{"field": "card_count", "message": "must be between 1 and 150"}},
				})
				return
			}
		}
	}

	difficulty := c.PostForm("difficulty")
	if difficulty == "" {
		difficulty = "intermediate"
	}

	language := c.PostForm("language")
	if language == "" {
		language = "ru"
	}

	setName := c.PostForm("set_name")
	if setName == "" {
		setName = "AI Generated Set from Image"
	}

	// Generate cards from image
	resp, err := h.service.GenerateCardsFromImage(c.Request.Context(), userID, services.GenerateCardsFromImageRequest{
		ImageData:  imageData,
		CardCount:  cardCount,
		Difficulty: difficulty,
		Language:   language,
		SetName:    setName,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to generate cards from image: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": resp,
	})
}
