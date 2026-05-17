package services

import (
	"context"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/storage"
)

type QuizService struct {
	cardStorage storage.CardStorage
}

func NewQuizService(cardStorage storage.CardStorage) *QuizService {
	return &QuizService{cardStorage: cardStorage}
}

func (s *QuizService) StartQuizSession(ctx context.Context, setID, userID string, questionCount int) (*models.QuizSession, error) {
	cards, err := s.cardStorage.GetCardsForQuiz(ctx, setID, int32(questionCount))
	if err != nil {
		return nil, err
	}

	if len(cards) < 4 {
		return nil, ErrNotFound
	}

	questions := make([]models.QuizQuestion, 0, len(cards))
	for _, card := range cards {
		options, correctIndex := s.generateOptions(card, cards)
		questions = append(questions, models.QuizQuestion{
			CardID:       card.ID,
			Front:        card.Front,
			Back:         card.Back,
			Options:      options,
			CorrectIndex: correctIndex,
		})
	}

	session := &models.QuizSession{
		ID:            uuid.New().String(),
		SetID:         setID,
		UserID:        userID,
		QuestionCount: len(questions),
		Questions:     questions,
		CreatedAt:     time.Now(),
	}

	return session, nil
}

func (s *QuizService) generateOptions(correctCard models.Card, allCards []models.Card) ([]models.QuizOption, int) {
	options := make([]models.QuizOption, 0, 4)
	correctIndex := rand.Intn(4)

	wrongAnswers := s.getWrongAnswers(correctCard, allCards, 3)

	for i := 0; i < 4; i++ {
		if i == correctIndex {
			options = append(options, models.QuizOption{
				ID:        uuid.New().String(),
				Text:      correctCard.Back,
				IsCorrect: true,
			})
		} else {
			if len(wrongAnswers) > 0 {
				wrong := wrongAnswers[0]
				wrongAnswers = wrongAnswers[1:]
				options = append(options, models.QuizOption{
					ID:        uuid.New().String(),
					Text:      wrong.Back,
					IsCorrect: false,
				})
			} else {
				options = append(options, models.QuizOption{
					ID:        uuid.New().String(),
					Text:      "Неверный вариант",
					IsCorrect: false,
				})
			}
		}
	}

	return options, correctIndex
}

func (s *QuizService) getWrongAnswers(correctCard models.Card, allCards []models.Card, count int) []models.Card {
	wrong := make([]models.Card, 0, count)
	for _, card := range allCards {
		if card.ID != correctCard.ID && len(wrong) < count {
			wrong = append(wrong, card)
		}
	}
	return wrong
}

func (s *QuizService) SubmitAnswer(ctx context.Context, session *models.QuizSession, questionIndex, selectedIndex int) (*models.QuizAnswerResult, error) {
	if questionIndex < 0 || questionIndex >= len(session.Questions) {
		return nil, ErrNotFound
	}

	question := session.Questions[questionIndex]
	isCorrect := selectedIndex == question.CorrectIndex

	result := &models.QuizAnswerResult{
		QuestionIndex: questionIndex,
		IsCorrect:     isCorrect,
		CorrectIndex:  question.CorrectIndex,
	}

	if !isCorrect {
		result.Explanation = question.Back
	}

	return result, nil
}

func (s *QuizService) CalculateQuizResult(session *models.QuizSession, answers []models.QuizAnswerResult, timeSpentMs int64) *models.QuizResult {
	correct := 0
	for _, answer := range answers {
		if answer.IsCorrect {
			correct++
		}
	}

	total := len(session.Questions)
	score := float32(0)
	if total > 0 {
		score = float32(correct) / float32(total) * 100
	}

	return &models.QuizResult{
		SessionID:        session.ID,
		TotalQuestions:   total,
		CorrectAnswers:   correct,
		IncorrectAnswers: total - correct,
		ScorePercentage:  score,
		TimeSpentMs:      timeSpentMs,
	}
}
