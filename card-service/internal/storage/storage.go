package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/karto4ki/karto4ki-backend/card-service/internal/models"
	"github.com/karto4ki/karto4ki-backend/shared/postgres"
	"github.com/lib/pq"
)

type CardSetStorage interface {
	Create(ctx context.Context, set *models.CardSet) error
	GetByID(ctx context.Context, id string) (*models.CardSet, error)
	GetByOwner(ctx context.Context, ownerID string, offset, limit int32) ([]models.CardSet, error)
	Update(ctx context.Context, set *models.CardSet) error
	Delete(ctx context.Context, id string) error
	GetPublic(ctx context.Context, query string, offset, limit int32) ([]models.CardSet, error)
}

type CardStorage interface {
	Create(ctx context.Context, card *models.Card) error
	GetByID(ctx context.Context, id string) (*models.Card, error)
	GetBySetID(ctx context.Context, setID string, offset, limit int32) ([]models.Card, error)
	Update(ctx context.Context, card *models.Card) error
	Delete(ctx context.Context, id string) error
	GetCountBySet(ctx context.Context, setID string) (int32, error)
	GetCardsForStudy(ctx context.Context, setID string, sessionType models.SessionType, limit int32) ([]models.Card, error)
	GetCardsForStudyAll(ctx context.Context, userID string, sessionType models.SessionType, limit int32) ([]models.Card, error)
	GetCardsForQuiz(ctx context.Context, setID string, limit int32) ([]models.Card, error)
	UpdateCardStatus(ctx context.Context, cardID string, status models.CardStatus, errorCount int32, lastRating models.CardRating, nextReview time.Time, streak int32) error
}

type StudySessionStorage interface {
	Create(ctx context.Context, session *models.StudySession) error
	GetByID(ctx context.Context, id string) (*models.StudySession, error)
	Delete(ctx context.Context, id string) error
}

type StatisticsStorage interface {
	GetSetStatistics(ctx context.Context, setID string) (*models.SetStatistics, error)
	GetUserStatistics(ctx context.Context, userID string) (*models.UserStatistics, error)
	RecordStudySession(ctx context.Context, userID, setID string, cardsStudied int32, timeSpentMinutes int32) error
}

type cardSetStorage struct {
	db *postgres.DB
}

func NewCardSetStorage(db *postgres.DB) CardSetStorage {
	return &cardSetStorage{db: db}
}

func (s *cardSetStorage) Create(ctx context.Context, set *models.CardSet) error {
	query := `INSERT INTO card_sets (id, owner_id, name, description, is_public, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.db.ExecContext(ctx, query, set.ID, set.OwnerID, set.Name, set.Description, set.IsPublic, set.CreatedAt)
	return err
}

func (s *cardSetStorage) GetByID(ctx context.Context, id string) (*models.CardSet, error) {
	query := `SELECT id, owner_id, name, description, is_public, created_at FROM card_sets WHERE id = $1`
	set := &models.CardSet{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&set.ID, &set.OwnerID, &set.Name, &set.Description, &set.IsPublic, &set.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return set, nil
}

func (s *cardSetStorage) GetByOwner(ctx context.Context, ownerID string, offset, limit int32) ([]models.CardSet, error) {
	query := `SELECT id, owner_id, name, description, is_public, created_at FROM card_sets 
			  WHERE owner_id = $1 ORDER BY created_at DESC OFFSET $2 LIMIT $3`
	rows, err := s.db.QueryContext(ctx, query, ownerID, offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sets []models.CardSet
	for rows.Next() {
		var set models.CardSet
		if err := rows.Scan(&set.ID, &set.OwnerID, &set.Name, &set.Description, &set.IsPublic, &set.CreatedAt); err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}
	return sets, rows.Err()
}

func (s *cardSetStorage) Update(ctx context.Context, set *models.CardSet) error {
	query := `UPDATE card_sets SET name = $1, description = $2, is_public = $3 WHERE id = $4`
	_, err := s.db.ExecContext(ctx, query, set.Name, set.Description, set.IsPublic, set.ID)
	return err
}

func (s *cardSetStorage) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM card_sets WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

func (s *cardSetStorage) GetPublic(ctx context.Context, query string, offset, limit int32) ([]models.CardSet, error) {
	sqlQuery := `SELECT id, owner_id, name, description, is_public, created_at FROM card_sets 
				 WHERE is_public = true AND name ILIKE $1 ORDER BY created_at DESC OFFSET $2 LIMIT $3`
	rows, err := s.db.QueryContext(ctx, sqlQuery, "%"+query+"%", offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sets []models.CardSet
	for rows.Next() {
		var set models.CardSet
		if err := rows.Scan(&set.ID, &set.OwnerID, &set.Name, &set.Description, &set.IsPublic, &set.CreatedAt); err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}
	return sets, rows.Err()
}

type cardStorage struct {
	db *postgres.DB
}

func NewCardStorage(db *postgres.DB) CardStorage {
	return &cardStorage{db: db}
}

func (c *cardStorage) Create(ctx context.Context, card *models.Card) error {
	query := `INSERT INTO cards (id, set_id, front, back, image_url, audio_url, status, error_count, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := c.db.ExecContext(ctx, query, card.ID, card.SetID, card.Front, card.Back, card.ImageURL, card.AudioURL, card.Status, card.ErrorCount, card.CreatedAt)
	return err
}

func (c *cardStorage) GetByID(ctx context.Context, id string) (*models.Card, error) {
	query := `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, next_review, created_at FROM cards WHERE id = $1`
	card := &models.Card{}
	var nextReview sql.NullTime
	err := c.db.QueryRowContext(ctx, query, id).Scan(
		&card.ID, &card.SetID, &card.Front, &card.Back, &card.ImageURL, &card.AudioURL, &card.Status, &card.ErrorCount, &nextReview, &card.CreatedAt,
	)
	if nextReview.Valid {
		card.NextReview = &nextReview.Time
	}
	if err != nil {
		return nil, err
	}
	return card, nil
}

func (c *cardStorage) GetBySetID(ctx context.Context, setID string, offset, limit int32) ([]models.Card, error) {
	query := `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, next_review, created_at FROM cards
			  WHERE set_id = $1 ORDER BY created_at DESC OFFSET $2 LIMIT $3`
	rows, err := c.db.QueryContext(ctx, query, setID, offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cards []models.Card
	for rows.Next() {
		var card models.Card
		var nextReview sql.NullTime
		if err := rows.Scan(&card.ID, &card.SetID, &card.Front, &card.Back, &card.ImageURL, &card.AudioURL, &card.Status, &card.ErrorCount, &nextReview, &card.CreatedAt); err != nil {
			return nil, err
		}
		if nextReview.Valid {
			card.NextReview = &nextReview.Time
		}
		cards = append(cards, card)
	}
	return cards, rows.Err()
}

func (c *cardStorage) Update(ctx context.Context, card *models.Card) error {
	query := `UPDATE cards SET front = $1, back = $2, image_url = $3, audio_url = $4, error_count = $5 WHERE id = $6`
	_, err := c.db.ExecContext(ctx, query, card.Front, card.Back, card.ImageURL, card.AudioURL, card.ErrorCount, card.ID)
	return err
}

func (c *cardStorage) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM cards WHERE id = $1`
	_, err := c.db.ExecContext(ctx, query, id)
	return err
}

func (c *cardStorage) GetCountBySet(ctx context.Context, setID string) (int32, error) {
	query := `SELECT COUNT(*) FROM cards WHERE set_id = $1`
	var count int32
	err := c.db.QueryRowContext(ctx, query, setID).Scan(&count)
	return count, err
}

func (c *cardStorage) GetCardsForStudy(ctx context.Context, setID string, sessionType models.SessionType, limit int32) ([]models.Card, error) {
	var query string
	switch sessionType {
	case models.SessionTypeReview:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = $1 AND (next_review IS NULL OR next_review <= NOW())
				 ORDER BY
					CASE WHEN next_review IS NULL THEN 0 ELSE 1 END,
					error_count DESC,
					next_review ASC
				 LIMIT $2`
	case models.SessionTypeLearn:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = $1
				 ORDER BY
					last_rating ASC,
					CASE WHEN next_review IS NULL OR next_review <= NOW() THEN 0 ELSE 1 END,
					error_count DESC,
					created_at ASC
				 LIMIT $2`
	case models.SessionTypeTest:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = $1 ORDER BY RANDOM() LIMIT $2`
	case models.SessionTypeAudio:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = $1 AND audio_url IS NOT NULL ORDER BY RANDOM() LIMIT $2`
	default:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = $1 ORDER BY last_rating ASC, error_count DESC, created_at ASC LIMIT $2`
	}

	rows, err := c.db.QueryContext(ctx, query, setID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cards []models.Card
	for rows.Next() {
		var card models.Card
		var nextReview sql.NullTime
		if err := rows.Scan(&card.ID, &card.SetID, &card.Front, &card.Back, &card.ImageURL, &card.AudioURL, &card.Status, &card.ErrorCount, &card.LastRating, &nextReview, &card.CreatedAt); err != nil {
			return nil, err
		}
		if nextReview.Valid {
			card.NextReview = &nextReview.Time
		}
		cards = append(cards, card)
	}
	return cards, rows.Err()
}

// GetCardsForStudyAll returns cards from ALL sets owned by the user for study
func (c *cardStorage) GetCardsForStudyAll(ctx context.Context, userID string, sessionType models.SessionType, limit int32) ([]models.Card, error) {
	setsQuery := `SELECT id FROM card_sets WHERE owner_id = $1`
	setRows, err := c.db.QueryContext(ctx, setsQuery, userID)
	if err != nil {
		return nil, err
	}
	defer setRows.Close()

	var setIDs []string
	for setRows.Next() {
		var setID string
		if err := setRows.Scan(&setID); err != nil {
			return nil, err
		}
		setIDs = append(setIDs, setID)
	}

	if len(setIDs) == 0 {
		return []models.Card{}, nil
	}

	var query string
	switch sessionType {
	case models.SessionTypeReview:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = ANY($1) AND (next_review IS NULL OR next_review <= NOW())
				 ORDER BY
					CASE WHEN next_review IS NULL THEN 0 ELSE 1 END,
					error_count DESC,
					next_review ASC
				 LIMIT $2`
	case models.SessionTypeLearn:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = ANY($1)
				 ORDER BY
					last_rating ASC,
					CASE WHEN next_review IS NULL OR next_review <= NOW() THEN 0 ELSE 1 END,
					error_count DESC,
					created_at ASC
				 LIMIT $2`
	case models.SessionTypeTest:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = ANY($1) ORDER BY RANDOM() LIMIT $2`
	case models.SessionTypeAudio:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = ANY($1) AND audio_url IS NOT NULL ORDER BY RANDOM() LIMIT $2`
	default:
		query = `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
				 WHERE set_id = ANY($1) ORDER BY last_rating ASC, error_count DESC, created_at ASC LIMIT $2`
	}

	rows, err := c.db.QueryContext(ctx, query, pq.Array(setIDs), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cards []models.Card
	for rows.Next() {
		var card models.Card
		var nextReview sql.NullTime
		if err := rows.Scan(&card.ID, &card.SetID, &card.Front, &card.Back, &card.ImageURL, &card.AudioURL, &card.Status, &card.ErrorCount, &card.LastRating, &nextReview, &card.CreatedAt); err != nil {
			return nil, err
		}
		if nextReview.Valid {
			card.NextReview = &nextReview.Time
		}
		cards = append(cards, card)
	}
	return cards, rows.Err()
}

func (c *cardStorage) GetCardsForQuiz(ctx context.Context, setID string, limit int32) ([]models.Card, error) {
	query := `SELECT id, set_id, front, back, image_url, audio_url, status, error_count, last_rating, next_review, created_at FROM cards
			  WHERE set_id = $1 ORDER BY RANDOM() LIMIT $2`

	rows, err := c.db.QueryContext(ctx, query, setID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cards []models.Card
	for rows.Next() {
		var card models.Card
		var nextReview sql.NullTime
		if err := rows.Scan(&card.ID, &card.SetID, &card.Front, &card.Back, &card.ImageURL, &card.AudioURL, &card.Status, &card.ErrorCount, &card.LastRating, &nextReview, &card.CreatedAt); err != nil {
			return nil, err
		}
		if nextReview.Valid {
			card.NextReview = &nextReview.Time
		}
		cards = append(cards, card)
	}
	return cards, rows.Err()
}

func (c *cardStorage) UpdateCardStatus(ctx context.Context, cardID string, status models.CardStatus, errorCount int32, lastRating models.CardRating, nextReview time.Time, streak int32) error {
	query := `UPDATE cards SET status = $1, error_count = $2, last_rating = $3, next_review = $4 WHERE id = $5`
	_, err := c.db.ExecContext(ctx, query, status, errorCount, lastRating, nextReview, cardID)
	return err
}

type studySessionStorage struct {
	db *postgres.DB
}

func NewStudySessionStorage(db *postgres.DB) StudySessionStorage {
	return &studySessionStorage{db: db}
}

func (s *studySessionStorage) Create(ctx context.Context, session *models.StudySession) error {
	query := `INSERT INTO study_sessions (id, set_id, user_id, session_type, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.ExecContext(ctx, query, session.ID, session.SetID, session.UserID, session.SessionType, session.CreatedAt)
	return err
}

func (s *studySessionStorage) GetByID(ctx context.Context, id string) (*models.StudySession, error) {
	query := `SELECT id, set_id, user_id, session_type, created_at FROM study_sessions WHERE id = $1`
	session := &models.StudySession{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(&session.ID, &session.SetID, &session.UserID, &session.SessionType, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *studySessionStorage) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM study_sessions WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

type statisticsStorage struct {
	db *postgres.DB
}

func NewStatisticsStorage(db *postgres.DB) StatisticsStorage {
	return &statisticsStorage{db: db}
}

func (s *statisticsStorage) GetSetStatistics(ctx context.Context, setID string) (*models.SetStatistics, error) {
	stats := &models.SetStatistics{SetID: setID}

	query := `SELECT
			  COUNT(*) FILTER (WHERE status = 'new') as new_cards,
			  COUNT(*) FILTER (WHERE status = 'learning') as learning_cards,
			  COUNT(*) FILTER (WHERE status IN ('reviewing', 'mastered')) as learned_cards,
			  COUNT(*) as total_cards
			  FROM cards WHERE set_id = $1`
	err := s.db.QueryRowContext(ctx, query, setID).Scan(&stats.NewCards, &stats.LearningCards, &stats.LearnedCards, &stats.TotalCards)
	if err != nil {
		return nil, err
	}

	if stats.TotalCards > 0 {
		stats.MasteryPercentage = float32(stats.LearnedCards) / float32(stats.TotalCards) * 100
	}

	historyQuery := `SELECT study_date, cards_studied, time_spent_minutes
					 FROM study_history
					 WHERE set_id = $1 AND study_date >= CURRENT_DATE - INTERVAL '7 days'
					 ORDER BY study_date DESC`
	rows, err := s.db.QueryContext(ctx, historyQuery, setID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var day models.StudyDay
		if err := rows.Scan(&day.Date, &day.CardsStudied, &day.TimeSpentMinutes); err != nil {
			return nil, err
		}
		stats.StudyHistory = append(stats.StudyHistory, day)
	}

	return stats, nil
}

func (s *statisticsStorage) GetUserStatistics(ctx context.Context, userID string) (*models.UserStatistics, error) {
	stats := &models.UserStatistics{}

	query := `SELECT
			  COUNT(DISTINCT cs.id) as total_sets,
			  COUNT(DISTINCT c.id) as total_cards,
			  COUNT(DISTINCT c.id) FILTER (WHERE c.status IN ('reviewing', 'mastered')) as learned_cards
			  FROM card_sets cs
			  LEFT JOIN cards c ON cs.id = c.set_id
			  WHERE cs.owner_id = $1`
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&stats.TotalSets, &stats.TotalCards, &stats.LearnedCards)
	if err != nil {
		return nil, err
	}

	streakQuery := `SELECT
					COUNT(DISTINCT study_date) FILTER (WHERE study_date >= CURRENT_DATE - INTERVAL '7 days') as current_streak,
					SUM(time_spent_minutes) FILTER (WHERE study_date >= CURRENT_DATE - INTERVAL '30 days') as total_time
					FROM study_history
					WHERE user_id = $1`
	err = s.db.QueryRowContext(ctx, streakQuery, userID).Scan(&stats.CurrentStreak, &stats.TotalStudyTimeMinutes)
	if err != nil {
		stats.CurrentStreak = 0
		stats.TotalStudyTimeMinutes = 0
	}

	longestStreakQuery := `SELECT COUNT(*) as streak
						   FROM (
								SELECT study_date,
									   study_date - (ROW_NUMBER() OVER (ORDER BY study_date))::int * INTERVAL '1 day' as grp
								FROM study_history
								WHERE user_id = $1
						   ) sub
						   GROUP BY grp
						   ORDER BY streak DESC
						   LIMIT 1`
	err = s.db.QueryRowContext(ctx, longestStreakQuery, userID).Scan(&stats.LongestStreak)
	if err != nil {
		stats.LongestStreak = 0
	}

	lastDateQuery := `SELECT MAX(study_date) FROM study_history WHERE user_id = $1`
	var lastDate sql.NullTime
	err = s.db.QueryRowContext(ctx, lastDateQuery, userID).Scan(&lastDate)
	if err == nil && lastDate.Valid {
		stats.LastStudyDate = &lastDate.Time
	}

	historyQuery := `SELECT study_date, SUM(cards_studied) as cards_studied, SUM(time_spent_minutes) as time_spent_minutes
					 FROM study_history
					 WHERE user_id = $1 AND study_date >= CURRENT_DATE - INTERVAL '7 days'
					 GROUP BY study_date
					 ORDER BY study_date DESC`
	rows, err := s.db.QueryContext(ctx, historyQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var day models.StudyDay
		if err := rows.Scan(&day.Date, &day.CardsStudied, &day.TimeSpentMinutes); err != nil {
			return nil, err
		}
		stats.StudyHistory = append(stats.StudyHistory, day)
	}

	return stats, nil
}

func (s *statisticsStorage) RecordStudySession(ctx context.Context, userID, setID string, cardsStudied int32, timeSpentMinutes int32) error {
	query := `INSERT INTO study_history (user_id, set_id, cards_studied, time_spent_minutes, study_date)
			  VALUES ($1, $2, $3, $4, CURRENT_DATE)
			  ON CONFLICT (user_id, set_id, study_date) 
			  DO UPDATE SET cards_studied = study_history.cards_studied + $3, time_spent_minutes = study_history.time_spent_minutes + $4`
	_, err := s.db.ExecContext(ctx, query, userID, setID, cardsStudied, timeSpentMinutes)
	return err
}
