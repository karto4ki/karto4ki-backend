package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
)

type TaskStatusHandler struct {
	service *services.AIService
}

func NewTaskStatusHandler(service *services.AIService) *TaskStatusHandler {
	return &TaskStatusHandler{service: service}
}

func (h *TaskStatusHandler) GetTaskStatus(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": "task_id is required",
			"error_details": []gin.H{{"field": "task_id", "message": "task_id parameter is required"}},
		})
		return
	}

	task, err := h.service.GetGenerationTask(c.Request.Context(), taskID)
	if err != nil {
		if err.Error() == "task not found: "+taskID {
			c.JSON(http.StatusNotFound, gin.H{
				"error_type":    "not_found",
				"error_message": "Task not found",
				"error_details": []gin.H{{"field": "task_id", "message": "no task found with the provided ID"}},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": "Failed to get task status: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": task,
	})
}
