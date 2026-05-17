package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
)

type GenerateCardsFromTXTRequest struct {
	CardCount      int    `form:"card_count"`
	Difficulty     string `form:"difficulty"`
	Language       string `form:"language"`
	SetName        string `form:"set_name"`
	SetDescription string `form:"set_description"`
}

func (h *AIHandler) GenerateCardsFromTXT(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_type":    "unauthorized",
			"error_message": "User ID not found in token",
		})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "File is required",
			"error_details": []gin.H{{"field": "file", "message": "TXT file is required"}},
		})
		return
	}
	defer file.Close()

	if header.Size > 10*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "File too large",
			"error_details": []gin.H{{"field": "file", "message": "Maximum file size is 10MB"}},
		})
		return
	}

	text, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to read file",
			"error_details": []gin.H{{"field": "file", "message": err.Error()}},
		})
		return
	}

	content := strings.TrimSpace(string(text))
	if len(content) < 100 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "TXT contains insufficient text",
			"error_details": []gin.H{{"field": "file", "message": "TXT must contain at least 100 characters of text"}},
		})
		return
	}

	cardCount := 5
	if val := c.PostForm("card_count"); val != "" {
		if _, err := fmt.Sscanf(val, "%d", &cardCount); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_type":    "validation_failed",
				"error_message": "Invalid card_count",
				"error_details": []gin.H{{"field": "card_count", "message": "Must be a number"}},
			})
			return
		}
	}

	if cardCount < 1 || cardCount > 150 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "Invalid card count",
			"error_details": []gin.H{{"field": "card_count", "message": "card_count must be between 1 and 150"}},
		})
		return
	}

	difficulty := c.DefaultPostForm("difficulty", "intermediate")
	language := c.DefaultPostForm("language", "ru")
	setName := c.DefaultPostForm("set_name", "TXT Generated Set")
	setDescription := c.PostForm("set_description")

	taskID, err := h.service.GenerateCardsAsync(c.Request.Context(), userID, services.GenerateCardsRequest{
		Text:           content,
		CardCount:      cardCount,
		Difficulty:     difficulty,
		Language:       language,
		SetName:        setName,
		SetDescription: setDescription,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to generate cards: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"data": gin.H{
			"task_id": taskID,
			"status":  "pending",
		},
	})
}
