package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/sashabaranov/go-openai"
)

// VisionClient supports multimodal LLM APIsAs (text + images)
type VisionClient struct {
	client   *openai.Client
	model    string
	provider string
}

func NewVisionClient(apiKey, baseURL, model, provider string) *VisionClient {
	config := openai.DefaultConfig(apiKey)

	if baseURL != "" {
		config.BaseURL = baseURL
	}

	config.HTTPClient = &http.Client{
		Timeout: 120 * time.Second, // Longer timeout for image processing
	}

	return &VisionClient{
		client:   openai.NewClientWithConfig(config),
		model:    model,
		provider: provider,
	}
}

// GenerateCardsFromImage generates flashcards from an image using Vision API
func (c *VisionClient) GenerateCardsFromImage(ctx context.Context, imageData []byte, cardCount int, difficulty, language string) ([]GeneratedCard, error) {
	// Convert image to base64
	base64Image := base64.StdEncoding.EncodeToString(imageData)

	// Detect MIME type (simple detection based on magic bytes)
	mimeType := "image/jpeg" // default
	if len(imageData) > 8 {
		if imageData[0] == 0x89 && imageData[1] == 0x50 && imageData[2] == 0x4E && imageData[3] == 0x47 {
			mimeType = "image/png"
		} else if imageData[0] == 0x52 && imageData[1] == 0x49 && imageData[2] == 0x46 && imageData[3] == 0x46 {
			mimeType = "image/webp"
		}
	}

	dataURL := fmt.Sprintf("data:%s;base64,%s", mimeType, base64Image)

	prompt := buildCardGenerationPromptFromImage(cardCount, difficulty, language)

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are an expert educator specializing in creating high-quality flashcards from images. Extract text from the image and generate clear, concise flashcards.",
			},
			{
				Role: openai.ChatMessageRoleUser,
				MultiContent: []openai.ChatMessagePart{
					{
						Type: openai.ChatMessagePartTypeText,
						Text: prompt,
					},
					{
						Type:     openai.ChatMessagePartTypeImageURL,
						ImageURL: &openai.ChatMessageImageURL{URL: dataURL},
					},
				},
			},
		},
		Temperature: 0.7,
		MaxTokens:   2000,
	})

	if err != nil {
		return nil, fmt.Errorf("Vision API error: %w", err)
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

func buildCardGenerationPromptFromImage(cardCount int, difficulty, language string) string {
	difficultyInstr := map[string]string{
		"easy":         "Use simple language and focus on basic concepts.",
		"intermediate": "Include moderate complexity and relationships between concepts.",
		"advanced":     "Include detailed explanations and nuanced distinctions.",
	}

	return fmt.Sprintf(`Extract text from this image and create %d flashcards.

Requirements:
- First, extract all readable text from the image
- Create flashcards based on the extracted content
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

If the image contains no readable text or is not suitable for flashcards, explain what you see and suggest what type of content would work better.`,
		cardCount, difficultyInstr[difficulty], language)
}
