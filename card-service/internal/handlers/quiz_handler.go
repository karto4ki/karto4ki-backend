package handlers

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/services"
)

type QuizHandler struct {
	service *services.QuizService
	sessions sync.Map
}

func NewQuizHandler(service *services.QuizService) *QuizHandler {
	return &QuizHandler{service: service}
}

type StartQuizRequest struct {
	QuestionCount int `json:"question_count" binding:"required,min=4,max=50"`
}

type SubmitQuizAnswerRequest struct {
	QuestionIndex int  `json:"question_index" binding:"required,min=0"`
	SelectedIndex int  `json:"selected_index" binding:"required,min=0,max=3"`
	TimeSpentMs   int64 `json:"time_spent_ms"`
}

func (h *QuizHandler) StartQuizSession(c *gin.Context) {
	userID := c.GetString("user_id")
	setID := c.Param("setId")

	var req StartQuizRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": err.Error(),
		})
		return
	}

	session, err := h.service.StartQuizSession(c.Request.Context(), setID, userID, req.QuestionCount)
	if err == services.ErrNotFound {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "Not enough cards for quiz (minimum 4 cards required)",
		})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": err.Error(),
		})
		return
	}

	h.sessions.Store(session.ID, &QuizSessionState{
		Session:  session,
		Answers:  make([]models.QuizAnswerResult, 0),
		Started:  true,
	})

	c.JSON(http.StatusOK, gin.H{
		"data": session,
	})
}

type QuizSessionState struct {
	Session  *models.QuizSession
	Answers  []models.QuizAnswerResult
	Started  bool
	Finished bool
}

func (h *QuizHandler) SubmitAnswer(c *gin.Context) {
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	val, ok := h.sessions.Load(sessionID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "Quiz session not found",
		})
		return
	}

	state := val.(*QuizSessionState)
	if state.Session.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error_type":    "forbidden",
			"error_message": "Access denied",
		})
		return
	}

	var req SubmitQuizAnswerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_type":    "validation_failed",
			"error_message": err.Error(),
		})
		return
	}

	result, err := h.service.SubmitAnswer(c.Request.Context(), state.Session, req.QuestionIndex, req.SelectedIndex)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_type":    "internal",
			"error_message": err.Error(),
		})
		return
	}

	state.Answers = append(state.Answers, *result)
	h.sessions.Store(sessionID, state)

	c.JSON(http.StatusOK, gin.H{
		"data": result,
	})
}

func (h *QuizHandler) FinishQuiz(c *gin.Context) {
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	val, ok := h.sessions.Load(sessionID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error_type":    "not_found",
			"error_message": "Quiz session not found",
		})
		return
	}

	state := val.(*QuizSessionState)
	if state.Session.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error_type":    "forbidden",
			"error_message": "Access denied",
		})
		return
	}

	quizResult := h.service.CalculateQuizResult(state.Session, state.Answers, 0)

	h.sessions.Delete(sessionID)

	c.JSON(http.StatusOK, gin.H{
		"data": quizResult,
	})
}
