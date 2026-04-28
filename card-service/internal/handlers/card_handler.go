package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
)

type CardHandler struct {
	service *services.CardService
}

func NewCardHandler(service *services.CardService) *CardHandler {
	return &CardHandler{service: service}
}

type CreateCardRequest struct {
	Front    string  `json:"front" binding:"required"`
	Back     string  `json:"back" binding:"required"`
	ImageURL *string `json:"image_url"`
	AudioURL *string `json:"audio_url"`
}

func (h *CardHandler) CreateCard(c *gin.Context) {
	setID := c.Param("setId")
	var req CreateCardRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	card, err := h.service.CreateCard(c.Request.Context(), setID, req.Front, req.Back, req.ImageURL, req.AudioURL)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Set not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": card})
}

func (h *CardHandler) GetCard(c *gin.Context) {
	userID := c.GetString("user_id")
	cardID := c.Param("cardId")

	card, err := h.service.GetCard(c.Request.Context(), cardID, userID)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Card not found"})
		return
	}
	if err == services.ErrForbidden {
		c.JSON(http.StatusForbidden, gin.H{"error_type": "forbidden", "error_message": "Access denied"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": card})
}

func (h *CardHandler) GetCards(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")
	offset, _ := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 32)
	limit, _ := strconv.ParseInt(c.DefaultQuery("limit", "20"), 10, 32)

	cards, err := h.service.GetCards(c.Request.Context(), setID, userID, int32(offset), int32(limit))
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Set not found"})
		return
	}
	if err == services.ErrForbidden {
		c.JSON(http.StatusForbidden, gin.H{"error_type": "forbidden", "error_message": "Access denied"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"cards":  cards,
			"offset": offset,
			"count":  len(cards),
		},
	})
}

func (h *CardHandler) UpdateCard(c *gin.Context) {
	userID := c.GetString("user_id")
	cardID := c.Param("cardId")
	var req CreateCardRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	card, err := h.service.UpdateCard(c.Request.Context(), cardID, userID, req.Front, req.Back, req.ImageURL, req.AudioURL)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Card not found"})
		return
	}
	if err == services.ErrForbidden {
		c.JSON(http.StatusForbidden, gin.H{"error_type": "forbidden", "error_message": "Access denied"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": card})
}

func (h *CardHandler) DeleteCard(c *gin.Context) {
	userID := c.GetString("user_id")
	cardID := c.Param("cardId")

	err := h.service.DeleteCard(c.Request.Context(), cardID, userID)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Card not found"})
		return
	}
	if err == services.ErrForbidden {
		c.JSON(http.StatusForbidden, gin.H{"error_type": "forbidden", "error_message": "Access denied"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{}})
}
