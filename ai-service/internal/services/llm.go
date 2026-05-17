package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sashabaranov/go-openai"
)

var (
	ErrLLMUnavailable  = errors.New("LLM provider unavailable")
	ErrInvalidResponse = errors.New("invalid LLM response")
)

type LLMClient interface {
	GenerateCards(ctx context.Context, text string, cardCount int, difficulty, language string) ([]GeneratedCard, error)
	GenerateQuiz(ctx context.Context, text string, questionCount int, difficulty, language string) ([]QuizQuestion, error)
	Summarize(ctx context.Context, text string, language string) (string, error)
}

type GeneratedCard struct {
	Front string `json:"front"`
	Back  string `json:"back"`
}

type QuizQuestion struct {
	Question    string   `json:"question"`
	Options     []string `json:"options"`
	Answer      string   `json:"answer"`
	Explanation string   `json:"explanation,omitempty"`
}

type OpenAIClient struct {
	client   *openai.Client
	model    string
	provider string
}

func NewOpenAIClient(apiKey, baseURL, model, provider string) *OpenAIClient {
	config := openai.DefaultConfig(apiKey)

	if baseURL != "" {
		config.BaseURL = baseURL
	}

	config.HTTPClient = &http.Client{
		Timeout: 60 * time.Second,
	}

	return &OpenAIClient{
		client:   openai.NewClientWithConfig(config),
		model:    model,
		provider: provider,
	}
}

func (c *OpenAIClient) GenerateCards(ctx context.Context, text string, cardCount int, difficulty, language string) ([]GeneratedCard, error) {
	prompt := buildCardGenerationPrompt(text, cardCount, difficulty, language)

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are an expert educator specializing in creating high-quality flashcards. Generate clear, concise flashcards from the provided text.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		Temperature: 0.7,
		MaxTokens:   2000,
	})

	if err != nil {
		return nil, fmt.Errorf("LLM API error: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, ErrInvalidResponse
	}

	content := resp.Choices[0].Message.Content
	cards, err := parseCardsFromResponse(content)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	return cards, nil
}

func (c *OpenAIClient) GenerateQuiz(ctx context.Context, text string, questionCount int, difficulty, language string) ([]QuizQuestion, error) {
	prompt := buildQuizGenerationPrompt(text, questionCount, difficulty, language)

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are an expert educator specializing in creating quiz questions. Generate multiple-choice questions from the provided text.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		Temperature: 0.7,
		MaxTokens:   2500,
	})

	if err != nil {
		return nil, fmt.Errorf("LLM API error: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, ErrInvalidResponse
	}

	content := resp.Choices[0].Message.Content
	questions, err := parseQuizFromResponse(content)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	return questions, nil
}

func (c *OpenAIClient) Summarize(ctx context.Context, text string, language string) (string, error) {
	prompt := buildSummarizationPrompt(text, language)

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are an expert at summarizing complex texts concisely while preserving key information.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		Temperature: 0.5,
		MaxTokens:   1000,
	})
	
	if err != nil {
		return "", fmt.Errorf("LLM API error: %w", err)
	}
	
	if len(resp.Choices) == 0 {
		return "", ErrInvalidResponse
	}
	
	return resp.Choices[0].Message.Content, nil
}

func buildCardGenerationPrompt(text string, cardCount int, difficulty, language string) string {
	difficultyInstr := map[string]string{
		"easy":         "Use simple language and focus on basic concepts.",
		"intermediate": "Include moderate complexity and relationships between concepts.",
		"advanced":     "Include detailed explanations and nuanced distinctions.",
	}

	return fmt.Sprintf(`Create %d flashcards from the following text.

Requirements:
- Each card should have a clear question (front) and accurate answer (back)
- Focus on key concepts, definitions, and important facts
- Avoid trivial information
- IMPORTANT: Do not create duplicate cards. Each card should cover a unique concept.
- IMPORTANT: Vary your question formulations. For similar concepts, use different question styles (e.g., "What is...?", "Define...", "Explain...", "How does...?").
- %s
- Language: %s

Format your response as a JSON array:
[
  {"front": "Question 1", "back": "Answer 1"},
  {"front": "Question 2", "back": "Answer 2"}
]

Text to process:
%s`, cardCount, difficultyInstr[difficulty], language, text)
}

func buildQuizGenerationPrompt(text string, questionCount int, difficulty, language string) string {
	return fmt.Sprintf(`Create %d multiple-choice quiz questions from the following text.

Requirements:
- Each question should have 4 options (1 correct, 3 plausible distractors)
- Include explanation for the correct answer
- IMPORTANT: Do not create duplicate questions. Each question should test a unique concept.
- IMPORTANT: Vary your question styles (e.g., direct questions, scenario-based, "which of the following", etc.).
- Language: %s
- Difficulty: %s

Format your response as a JSON array:
[
  {
    "question": "Question text",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "answer": "Correct option text",
    "explanation": "Why this is correct"
  }
]

Text to process:
%s`, questionCount, language, difficulty, text)
}

func buildSummarizationPrompt(text string, language string) string {
	return fmt.Sprintf(`Summarize the following text in %s.

Requirements:
- Capture the main ideas and key points
- Keep it concise (3-5 sentences)
- Use clear, accessible language

Text to summarize:
%s`, language, text)
}

func parseCardsFromResponse(content string) ([]GeneratedCard, error) {
	var cards []GeneratedCard

	jsonStart := -1
	jsonEnd := -1
	bracketCount := 0
	inArray := false

	for i, ch := range content {
		if ch == '[' && !inArray {
			inArray = true
			jsonStart = i
			bracketCount = 1
		} else if inArray {
			if ch == '[' {
				bracketCount++
			} else if ch == ']' {
				bracketCount--
				if bracketCount == 0 {
					jsonEnd = i + 1
					break
				}
			}
		}
	}
	
	if jsonStart == -1 || jsonEnd == -1 {
		if err := json.Unmarshal([]byte(content), &cards); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
		return cards, nil
	}

	jsonStr := content[jsonStart:jsonEnd]
	if err := json.Unmarshal([]byte(jsonStr), &cards); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return cards, nil
}

func parseQuizFromResponse(content string) ([]QuizQuestion, error) {
	var questions []QuizQuestion

	jsonStart := -1
	jsonEnd := -1
	bracketCount := 0
	inArray := false

	for i, ch := range content {
		if ch == '[' && !inArray {
			inArray = true
			jsonStart = i
			bracketCount = 1
		} else if inArray {
			if ch == '[' {
				bracketCount++
			} else if ch == ']' {
				bracketCount--
				if bracketCount == 0 {
					jsonEnd = i + 1
					break
				}
			}
		}
	}

	if jsonStart == -1 || jsonEnd == -1 {
		if err := json.Unmarshal([]byte(content), &questions); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
		return questions, nil
	}

	jsonStr := content[jsonStart:jsonEnd]
	if err := json.Unmarshal([]byte(jsonStr), &questions); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return questions, nil
}

type MockLLMClient struct{}

func NewMockLLMClient() *MockLLMClient {
	return &MockLLMClient{}
}

func (m *MockLLMClient) GenerateCards(ctx context.Context, text string, cardCount int, difficulty, language string) ([]GeneratedCard, error) {
	return []GeneratedCard{
		{Front: "Mock question 1?", Back: "Mock answer 1"},
		{Front: "Mock question 2?", Back: "Mock answer 2"},
	}, nil
}

func (m *MockLLMClient) GenerateQuiz(ctx context.Context, text string, questionCount int, difficulty, language string) ([]QuizQuestion, error) {
	return []QuizQuestion{
		{
			Question:    "Mock question?",
			Options:     []string{"A", "B", "C", "D"},
			Answer:      "A",
			Explanation: "Because",
		},
	}, nil
}

func (m *MockLLMClient) Summarize(ctx context.Context, text string, language string) (string, error) {
	return "This is a mock summary of the provided text.", nil
}
