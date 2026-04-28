package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
)

type CardSetHandler struct {
	service *services.CardSetService
}

func NewCardSetHandler(service *services.CardSetService) *CardSetHandler {
	return &CardSetHandler{service: service}
}

type CreateCardSetRequest struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
	IsPublic    bool    `json:"is_public"`
}

func (h *CardSetHandler) CreateCardSet(c *gin.Context) {
	userID := c.GetString("user_id")
	var req CreateCardSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	set, err := h.service.CreateCardSet(c.Request.Context(), userID, req.Name, req.Description, req.IsPublic)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": set})
}

func (h *CardSetHandler) GetCardSet(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")

	set, err := h.service.GetCardSet(c.Request.Context(), setID, userID)
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

	c.JSON(http.StatusOK, gin.H{"data": set})
}

func (h *CardSetHandler) GetCardSets(c *gin.Context) {
	userID := c.GetString("user_id")
	offset, _ := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 32)
	limit, _ := strconv.ParseInt(c.DefaultQuery("limit", "10"), 10, 32)

	sets, err := h.service.GetCardSets(c.Request.Context(), userID, int32(offset), int32(limit))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"sets":   sets,
			"offset": offset,
			"count":  len(sets),
		},
	})
}

func (h *CardSetHandler) UpdateCardSet(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")
	var req CreateCardSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "validation_failed", "error_message": err.Error()})
		return
	}

	set, err := h.service.UpdateCardSet(c.Request.Context(), setID, userID, req.Name, req.Description, req.IsPublic)
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

	c.JSON(http.StatusOK, gin.H{"data": set})
}

func (h *CardSetHandler) DeleteCardSet(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")

	err := h.service.DeleteCardSet(c.Request.Context(), setID, userID)
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

	c.JSON(http.StatusOK, gin.H{"data": gin.H{}})
}

func (h *CardSetHandler) SearchPublicSets(c *gin.Context) {
	query := c.Query("query")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error_type": "invalid_param", "error_message": "query parameter is required"})
		return
	}

	offset, _ := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 32)
	limit, _ := strconv.ParseInt(c.DefaultQuery("limit", "10"), 10, 32)

	sets, err := h.service.SearchPublicSets(c.Request.Context(), query, int32(offset), int32(limit))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"sets":   sets,
			"offset": offset,
			"count":  len(sets),
		},
	})
}

func (h *CardSetHandler) CloneSet(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")

	clonedSet, err := h.service.CloneSet(c.Request.Context(), setID, userID)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error_type": "not_found", "error_message": "Set not found"})
		return
	}
	if err == services.ErrForbidden {
		c.JSON(http.StatusForbidden, gin.H{"error_type": "forbidden", "error_message": "Cannot clone private set"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_type": "internal", "error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": clonedSet})
}
