package services

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/clients"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/ai-service/internal/storage"
)

type AIService struct {
	llmClient   LLMClient
	cardClient  *clients.CardServiceClient
	httpClient  *http.Client
	taskStorage *storage.GenerationTaskStorage
}

func NewAIService(llmClient LLMClient, cardClient *clients.CardServiceClient, taskStorage *storage.GenerationTaskStorage) *AIService {
	return &AIService{
		llmClient:   llmClient,
		cardClient:  cardClient,
		taskStorage: taskStorage,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type GenerateCardsRequest struct {
	Text             string `json:"text"`
	CardCount        int    `json:"card_count,omitempty"`
	Difficulty       string `json:"difficulty,omitempty"`
	Language         string `json:"language,omitempty"`
	SetName          string `json:"set_name,omitempty"`
	SetDescription   string `json:"set_description,omitempty"`
}

type GenerateCardsResponse struct {
	SetID   string          `json:"set_id"`
	SetName string          `json:"set_name"`
	Cards   []GeneratedCard `json:"cards"`
}

type GenerateQuizRequest struct {
	Text          string `json:"text"`
	QuestionCount int    `json:"question_count,omitempty"`
	Difficulty    string `json:"difficulty,omitempty"`
	Language      string `json:"language,omitempty"`
}

type GenerateQuizResponse struct {
	Questions []QuizQuestion `json:"questions"`
}

type SummarizeRequest struct {
	Text     string `json:"text"`
	Language string `json:"language,omitempty"`
}

type SummarizeResponse struct {
	Summary string `json:"summary"`
}

// GenerateCardsAsync starts an async card generation task and returns task ID
func (s *AIService) GenerateCardsAsync(ctx context.Context, userID string, req GenerateCardsRequest) (string, error) {
	if req.CardCount <= 0 {
		req.CardCount = 5
	}
	if req.Difficulty == "" {
		req.Difficulty = "intermediate"
	}
	if req.Language == "" {
		req.Language = "ru"
	}
	if req.SetName == "" {
		req.SetName = "AI Generated Set"
	}

	// Create task
	taskID := uuid.New().String()
	task := &models.GenerationTask{
		TaskID:        taskID,
		UserID:        userID,
		Status:        models.TaskStatusPending,
		Progress:      0,
		TotalCards:    req.CardCount,
		GeneratedCards: 0,
		SetName:       req.SetName,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.taskStorage.CreateTask(ctx, task); err != nil {
		return "", fmt.Errorf("create task: %w", err)
	}

	// Start async generation
	go s.processGeneration(ctx, taskID, req, userID)

	return taskID, nil
}

// processGeneration handles the actual card generation in background
func (s *AIService) processGeneration(ctx context.Context, taskID string, req GenerateCardsRequest, userID string) {
	// Update status to processing
	if err := s.taskStorage.UpdateProgress(ctx, taskID, 0, models.TaskStatusProcessing); err != nil {
		return
	}

	// Generate cards from LLM
	cards, err := s.llmClient.GenerateCards(ctx, req.Text, req.CardCount, req.Difficulty, req.Language)
	if err != nil {
		_ = s.taskStorage.FailTask(ctx, taskID, fmt.Sprintf("LLM generation failed: %v", err))
		return
	}

	// Update progress after LLM generation
	if err := s.taskStorage.UpdateProgress(ctx, taskID, len(cards), models.TaskStatusProcessing); err != nil {
		return
	}

	// Create card set
	var description *string
	if req.SetDescription != "" {
		description = &req.SetDescription
	}
	setID, err := s.createCardSet(ctx, userID, req.SetName, description)
	if err != nil {
		_ = s.taskStorage.FailTask(ctx, taskID, fmt.Sprintf("Failed to create card set: %v", err))
		return
	}

	// Create individual cards with progress updates
	for i, card := range cards {
		if err := s.createCard(ctx, setID, card.Front, card.Back, nil, nil); err != nil {
			_ = s.deleteCardSet(ctx, setID, userID)
			_ = s.taskStorage.FailTask(ctx, taskID, fmt.Sprintf("Failed to create card %d: %v", i+1, err))
			return
		}
		// Update progress after each card
		_ = s.taskStorage.UpdateProgress(ctx, taskID, i+1, models.TaskStatusProcessing)
	}

	// Mark task as completed
	if err := s.taskStorage.CompleteTask(ctx, taskID, setID); err != nil {
		return
	}
}

// GetGenerationTask retrieves the current state of a generation task
func (s *AIService) GetGenerationTask(ctx context.Context, taskID string) (*models.GenerationTask, error) {
	task, err := s.taskStorage.GetTask(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}
	return task, nil
}

// GenerateCards generates cards synchronously (legacy, kept for backward compatibility)
func (s *AIService) GenerateCards(ctx context.Context, userID string, req GenerateCardsRequest) (*GenerateCardsResponse, error) {
	if req.CardCount <= 0 {
		req.CardCount = 5
	}
	if req.Difficulty == "" {
		req.Difficulty = "intermediate"
	}
	if req.Language == "" {
		req.Language = "ru"
	}
	if req.SetName == "" {
		req.SetName = "AI Generated Set"
	}

	cards, err := s.llmClient.GenerateCards(ctx, req.Text, req.CardCount, req.Difficulty, req.Language)
	if err != nil {
		return nil, fmt.Errorf("generate cards: %w", err)
	}

	var description *string
	if req.SetDescription != "" {
		description = &req.SetDescription
	}
	setID, err := s.createCardSet(ctx, userID, req.SetName, description)
	if err != nil {
		return nil, fmt.Errorf("create card set: %w", err)
	}

	for _, card := range cards {
		if err := s.createCard(ctx, setID, card.Front, card.Back, nil, nil); err != nil {
			_ = s.deleteCardSet(ctx, setID, userID)
			return nil, fmt.Errorf("create card: %w", err)
		}
	}

	return &GenerateCardsResponse{
		SetID:   setID,
		SetName: req.SetName,
		Cards:   cards,
	}, nil
}

func (s *AIService) GenerateQuiz(ctx context.Context, req GenerateQuizRequest) (*GenerateQuizResponse, error) {
	if req.QuestionCount <= 0 {
		req.QuestionCount = 5
	}
	if req.Difficulty == "" {
		req.Difficulty = "intermediate"
	}
	if req.Language == "" {
		req.Language = "ru"
	}

	questions, err := s.llmClient.GenerateQuiz(ctx, req.Text, req.QuestionCount, req.Difficulty, req.Language)
	if err != nil {
		return nil, fmt.Errorf("generate quiz: %w", err)
	}

	return &GenerateQuizResponse{
		Questions: questions,
	}, nil
}

func (s *AIService) Summarize(ctx context.Context, req SummarizeRequest) (*SummarizeResponse, error) {
	if req.Language == "" {
		req.Language = "ru"
	}

	summary, err := s.llmClient.Summarize(ctx, req.Text, req.Language)
	if err != nil {
		return nil, fmt.Errorf("summarize: %w", err)
	}

	return &SummarizeResponse{
		Summary: summary,
	}, nil
}

func (s *AIService) createCardSet(ctx context.Context, userID, name string, description *string) (string, error) {
	result, err := s.cardClient.CreateCardSet(ctx, userID, name, description, false)
	if err != nil {
		return "", err
	}
	return result.SetID, nil
}

func (s *AIService) createCard(ctx context.Context, setID, front, back string, imageURL, audioURL *string) error {
	_, err := s.cardClient.CreateCard(ctx, setID, front, back, imageURL, audioURL)
	return err
}

func (s *AIService) deleteCardSet(ctx context.Context, setID, userID string) error {
	_, err := s.cardClient.DeleteCardSet(ctx, setID, userID)
	return err
}
