package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type internalTokenKey struct{}

type AIService struct {
	llmClient      LLMClient
	cardServiceURL string
	httpClient     *http.Client
}

func NewAIService(llmClient LLMClient, cardServiceURL string, timeout time.Duration) *AIService {
	return &AIService{
		llmClient:      llmClient,
		cardServiceURL: cardServiceURL,
		httpClient: &http.Client{
			Timeout: timeout,
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

func (s *AIService) GenerateCards(ctx context.Context, userID, internalToken string, req GenerateCardsRequest) (*GenerateCardsResponse, error) {
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

	ctx = context.WithValue(ctx, internalTokenKey{}, internalToken)

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
			_ = s.deleteCardSet(ctx, setID)
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
	type createSetRequest struct {
		Name        string  `json:"name"`
		Description *string `json:"description,omitempty"`
		IsPublic    bool    `json:"is_public"`
	}

	body := createSetRequest{
		Name:        name,
		Description: description,
		IsPublic:    false,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("%s/v1.0/sets", s.cardServiceURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-Token", ctx.Value(internalTokenKey{}).(string))
	httpReq.Header.Set("Idempotency-Key", uuid.New().String())

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("card service returned status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Data.ID, nil
}

func (s *AIService) createCard(ctx context.Context, setID, front, back string, imageURL, audioURL *string) error {
	type createCardRequest struct {
		Front    string  `json:"front"`
		Back     string  `json:"back"`
		ImageURL *string `json:"image_url,omitempty"`
		AudioURL *string `json:"audio_url,omitempty"`
	}

	body := createCardRequest{
		Front:    front,
		Back:     back,
		ImageURL: imageURL,
		AudioURL: audioURL,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/v1.0/sets/%s/cards", s.cardServiceURL, setID)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-Token", ctx.Value(internalTokenKey{}).(string))
	httpReq.Header.Set("Idempotency-Key", uuid.New().String())

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("card service returned status %d", resp.StatusCode)
	}

	return nil
}

func (s *AIService) deleteCardSet(ctx context.Context, setID string) error {
	reqURL := fmt.Sprintf("%s/v1.0/sets/%s", s.cardServiceURL, setID)
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", reqURL, nil)
	if err != nil {
		return err
	}

	httpReq.Header.Set("X-Internal-Token", ctx.Value(internalTokenKey{}).(string))

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("card service returned status %d", resp.StatusCode)
	}

	return nil
}
