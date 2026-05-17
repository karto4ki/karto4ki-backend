package services

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/card-service/internal/userclient"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrForbidden     = errors.New("forbidden")
	ErrInvalidParam  = errors.New("invalid parameter")
)

type CardSetService struct {
	setStorage   storage.CardSetStorage
	cardStorage  storage.CardStorage
	statsStorage storage.StatisticsStorage
	userClient   *userclient.Client
}

func NewCardSetService(setStorage storage.CardSetStorage, cardStorage storage.CardStorage, statsStorage storage.StatisticsStorage, userClient *userclient.Client) *CardSetService {
	return &CardSetService{
		setStorage:   setStorage,
		cardStorage:  cardStorage,
		statsStorage: statsStorage,
		userClient:   userClient,
	}
}

func (s *CardSetService) CreateCardSet(ctx context.Context, ownerID, name string, description *string, isPublic bool) (*models.CardSet, error) {
	set := &models.CardSet{
		ID:          uuid.New().String(),
		OwnerID:     ownerID,
		Name:        name,
		Description: description,
		IsPublic:    isPublic,
		CreatedAt:   time.Now(),
	}

	if err := s.setStorage.Create(ctx, set); err != nil {
		return nil, err
	}

	return set, nil
}

func (s *CardSetService) GetCardSet(ctx context.Context, id, userID string) (*models.CardSet, error) {
	set, err := s.setStorage.GetByID(ctx, id)
	if err != nil {
		return nil, ErrNotFound
	}

	if set.OwnerID != userID && !set.IsPublic {
		return nil, ErrForbidden
	}

	count, _ := s.cardStorage.GetCountBySet(ctx, id)
	set.CardCount = count

	stats, err := s.statsStorage.GetSetStatistics(ctx, id)
	if err == nil {
		set.LearnedCount = stats.LearnedCards
		if stats.TotalCards > 0 {
			set.MasteryPercentage = stats.MasteryPercentage
		}
	}

	if ownerInfo, err := s.userClient.GetPublicProfile(ctx, set.OwnerID); err == nil && ownerInfo != nil {
		set.Author = &models.AuthorInfo{
			ID:    ownerInfo.ID,
			Name:  ownerInfo.Name,
			Photo: ownerInfo.PhotoURL,
		}
	}

	return set, nil
}

func (s *CardSetService) GetCardSets(ctx context.Context, ownerID string, offset, limit int32) ([]models.CardSet, error) {
	sets, err := s.setStorage.GetByOwner(ctx, ownerID, offset, limit)
	if err != nil {
		return nil, err
	}

	for i := range sets {
		count, _ := s.cardStorage.GetCountBySet(ctx, sets[i].ID)
		sets[i].CardCount = count

		if ownerInfo, err := s.userClient.GetPublicProfile(ctx, sets[i].OwnerID); err == nil && ownerInfo != nil {
			sets[i].Author = &models.AuthorInfo{
				ID:    ownerInfo.ID,
				Name:  ownerInfo.Name,
				Photo: ownerInfo.PhotoURL,
			}
		}
	}

	return sets, nil
}

func (s *CardSetService) UpdateCardSet(ctx context.Context, id, userID, name string, description *string, isPublic bool) (*models.CardSet, error) {
	set, err := s.GetCardSet(ctx, id, userID)
	if err != nil {
		return nil, err
	}

	if set.OwnerID != userID {
		return nil, ErrForbidden
	}

	set.Name = name
	set.Description = description
	set.IsPublic = isPublic

	if err := s.setStorage.Update(ctx, set); err != nil {
		return nil, err
	}

	return set, nil
}

func (s *CardSetService) DeleteCardSet(ctx context.Context, id, userID string) error {
	set, err := s.GetCardSet(ctx, id, userID)
	if err != nil {
		return err
	}

	if set.OwnerID != userID {
		return ErrForbidden
	}

	return s.setStorage.Delete(ctx, id)
}

func (s *CardSetService) SearchPublicSets(ctx context.Context, query string, offset, limit int32) ([]models.CardSet, error) {
	return s.setStorage.GetPublic(ctx, query, offset, limit)
}

func (s *CardSetService) CloneSet(ctx context.Context, setID, userID string) (*models.CardSet, error) {
	originalSet, err := s.setStorage.GetByID(ctx, setID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if !originalSet.IsPublic {
		return nil, ErrForbidden
	}

	clonedSet := &models.CardSet{
		ID:          uuid.New().String(),
		OwnerID:     userID,
		Name:        originalSet.Name + " (copy)",
		Description: originalSet.Description,
		IsPublic:    false,
		CreatedAt:   time.Now(),
	}

	if err := s.setStorage.Create(ctx, clonedSet); err != nil {
		return nil, err
	}

	cards, err := s.cardStorage.GetBySetID(ctx, setID, 0, 1000)
	if err != nil {
		return nil, err
	}

	for _, card := range cards {
		clonedCard := &models.Card{
			ID:        uuid.New().String(),
			SetID:     clonedSet.ID,
			Front:     card.Front,
			Back:      card.Back,
			ImageURL:  card.ImageURL,
			AudioURL:  card.AudioURL,
			Status:    models.StatusNew,
			CreatedAt: time.Now(),
		}
		if err := s.cardStorage.Create(ctx, clonedCard); err != nil {
			return nil, err
		}
	}

	clonedSet.CardCount = int32(len(cards))

	if ownerInfo, err := s.userClient.GetPublicProfile(ctx, userID); err == nil && ownerInfo != nil {
		clonedSet.Author = &models.AuthorInfo{
			ID:    ownerInfo.ID,
			Name:  ownerInfo.Name,
			Photo: ownerInfo.PhotoURL,
		}
	}

	return clonedSet, nil
}

type CardService struct {
	setStorage storage.CardSetStorage
	cardStorage storage.CardStorage
}

func NewCardService(setStorage storage.CardSetStorage, cardStorage storage.CardStorage) *CardService {
	return &CardService{setStorage: setStorage, cardStorage: cardStorage}
}

func (s *CardService) CreateCard(ctx context.Context, setID, front, back string, imageURL, audioURL *string) (*models.Card, error) {
	_, err := s.setStorage.GetByID(ctx, setID)
	if err != nil {
		return nil, ErrNotFound
	}

	card := &models.Card{
		ID:        uuid.New().String(),
		SetID:     setID,
		Front:     front,
		Back:      back,
		ImageURL:  imageURL,
		AudioURL:  audioURL,
		Status:    models.StatusNew,
		CreatedAt: time.Now(),
	}

	if err := s.cardStorage.Create(ctx, card); err != nil {
		return nil, err
	}

	return card, nil
}

func (s *CardService) GetCard(ctx context.Context, id, userID string) (*models.Card, error) {
	card, err := s.cardStorage.GetByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	set, err := s.setStorage.GetByID(ctx, card.SetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if set.OwnerID != userID && !set.IsPublic {
		return nil, ErrForbidden
	}

	return card, nil
}

func (s *CardService) GetCards(ctx context.Context, setID, userID string, offset, limit int32) ([]models.Card, error) {
	set, err := s.setStorage.GetByID(ctx, setID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if set.OwnerID != userID && !set.IsPublic {
		return nil, ErrForbidden
	}

	return s.cardStorage.GetBySetID(ctx, setID, offset, limit)
}

func (s *CardService) UpdateCard(ctx context.Context, id, userID, front, back string, imageURL, audioURL *string) (*models.Card, error) {
	card, err := s.cardStorage.GetByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	set, err := s.setStorage.GetByID(ctx, card.SetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if set.OwnerID != userID {
		return nil, ErrForbidden
	}

	card.Front = front
	card.Back = back
	card.ImageURL = imageURL
	card.AudioURL = audioURL

	if err := s.cardStorage.Update(ctx, card); err != nil {
		return nil, err
	}

	return card, nil
}

func (s *CardService) DeleteCard(ctx context.Context, id, userID string) error {
	card, err := s.cardStorage.GetByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}

	set, err := s.setStorage.GetByID(ctx, card.SetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}

	if set.OwnerID != userID {
		return ErrForbidden
	}

	return s.cardStorage.Delete(ctx, id)
}

type LearningService struct {
	setStorage   storage.CardSetStorage
	cardStorage  storage.CardStorage
	sessionStorage storage.StudySessionStorage
	statsStorage storage.StatisticsStorage
}

func NewLearningService(setStorage storage.CardSetStorage, cardStorage storage.CardStorage, sessionStorage storage.StudySessionStorage, statsStorage storage.StatisticsStorage) *LearningService {
	return &LearningService{setStorage: setStorage, cardStorage: cardStorage, sessionStorage: sessionStorage, statsStorage: statsStorage}
}

func (s *LearningService) StartStudySession(ctx context.Context, setID, userID string, sessionType models.SessionType, limit int32) (*models.StudySession, error) {
	set, err := s.setStorage.GetByID(ctx, setID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if set.OwnerID != userID && !set.IsPublic {
		return nil, ErrForbidden
	}

	cards, err := s.cardStorage.GetCardsForStudy(ctx, setID, sessionType, limit)
	if err != nil {
		return nil, err
	}

	if len(cards) == 0 {
		return nil, ErrNotFound
	}

	session := &models.StudySession{
		ID:          uuid.New().String(),
		SetID:       setID,
		UserID:      userID,
		SessionType: sessionType,
		Cards:       cards,
		CreatedAt:   time.Now(),
	}

	if err := s.sessionStorage.Create(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// StartStudySessionAll starts a study session across ALL user's sets
func (s *LearningService) StartStudySessionAll(ctx context.Context, userID string, sessionType models.SessionType, limit int32) (*models.StudySession, error) {
	cards, err := s.cardStorage.GetCardsForStudyAll(ctx, userID, sessionType, limit)
	if err != nil {
		return nil, err
	}

	if len(cards) == 0 {
		return nil, ErrNotFound
	}

	session := &models.StudySession{
		ID:          uuid.New().String(),
		SetID:       "",
		UserID:      userID,
		SessionType: sessionType,
		Cards:       cards,
		CreatedAt:   time.Now(),
	}

	if err := s.sessionStorage.Create(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (s *LearningService) SubmitAnswer(ctx context.Context, sessionID, cardID, userID string, rating models.CardRating, timeSpentMs int64) (*AnswerResult, error) {
	session, err := s.sessionStorage.GetByID(ctx, sessionID)
	if err != nil {
		return nil, ErrNotFound
	}

	if session.UserID != userID {
		return nil, ErrForbidden
	}

	card, err := s.cardStorage.GetByID(ctx, cardID)
	if err != nil {
		return nil, ErrNotFound
	}

	newStatus, nextReview, streak, errorCount := CalculateSpacedRepetition(card.Status, card.ErrorCount, rating)

	if err := s.cardStorage.UpdateCardStatus(ctx, cardID, newStatus, errorCount, rating, nextReview, streak); err != nil {
		return nil, err
	}

	timeSpentMinutes := int32(timeSpentMs / 60000)
	if timeSpentMinutes < 1 {
		timeSpentMinutes = 1
	}
	_ = s.statsStorage.RecordStudySession(ctx, userID, session.SetID, 1, timeSpentMinutes)

	return &AnswerResult{
		CardID:     cardID,
		NewStatus:  newStatus,
		NextReview: nextReview,
		Streak:     streak,
		ErrorCount: errorCount,
		LastRating: rating,
	}, nil
}

func (s *LearningService) GetSetStatistics(ctx context.Context, setID string) (*models.SetStatistics, error) {
	return s.statsStorage.GetSetStatistics(ctx, setID)
}

func (s *LearningService) GetUserStatistics(ctx context.Context, userID string) (*models.UserStatistics, error) {
	return s.statsStorage.GetUserStatistics(ctx, userID)
}

func CalculateSpacedRepetition(currentStatus models.CardStatus, errorCount int32, rating models.CardRating) (models.CardStatus, time.Time, int32, int32) {
	var nextStatus models.CardStatus
	var daysUntilReview int
	var streak int32 = 1
	var newErrorCount int32 = errorCount

	if rating == models.RatingRemember {
		if newErrorCount > 0 {
			newErrorCount--
		}

		switch currentStatus {
		case models.StatusNew:
			nextStatus = models.StatusLearning
			daysUntilReview = 1
			streak = 1
		case models.StatusLearning:
			nextStatus = models.StatusReviewing
			daysUntilReview = 3
			streak = 2
		case models.StatusReviewing:
			nextStatus = models.StatusReviewing
			daysUntilReview = 7
			streak = 3
		case models.StatusMastered:
			nextStatus = models.StatusMastered
			daysUntilReview = 30
			streak = 5
		default:
			nextStatus = models.StatusLearning
			daysUntilReview = 1
		}
	} else {
		newErrorCount++

		nextStatus = models.StatusLearning
		daysUntilReview = 1
		streak = 0
	}

	nextReview := time.Now().AddDate(0, 0, daysUntilReview)
	return nextStatus, nextReview, streak, newErrorCount
}

type AnswerResult struct {
	CardID     string            `json:"card_id"`
	NewStatus  models.CardStatus `json:"new_status"`
	NextReview time.Time         `json:"next_review"`
	Streak     int32             `json:"streak"`
	ErrorCount int32             `json:"error_count"`
	LastRating models.CardRating `json:"last_rating"`
}
