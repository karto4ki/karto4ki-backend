package models

import "time"

type CardStatus string

const (
	StatusNew      CardStatus = "new"
	StatusLearning CardStatus = "learning"
	StatusReviewing CardStatus = "reviewing"
	StatusMastered CardStatus = "mastered"
)

type CardRating int

const (
	RatingForgot CardRating = 0
	RatingRemember CardRating = 1
)

type SessionType string

const (
	SessionTypeReview SessionType = "review"
	SessionTypeTest   SessionType = "test"
	SessionTypeAudio  SessionType = "audio"
	SessionTypeLearn  SessionType = "learn"
	SessionTypeQuiz   SessionType = "quiz"
	SessionTypeAll    SessionType = "all"
)

type QuizOption struct {
	ID         string `json:"id"`
	Text       string `json:"text"`
	IsCorrect  bool   `json:"is_correct"`
}

type QuizQuestion struct {
	CardID       string       `json:"card_id"`
	Front        string       `json:"front"`
	Back         string       `json:"back"`
	Options      []QuizOption `json:"options"`
	CorrectIndex int          `json:"correct_index"`
}

type QuizSession struct {
	ID          string         `json:"id"`
	SetID       string         `json:"set_id"`
	UserID      string         `json:"user_id"`
	QuestionCount int          `json:"question_count"`
	Questions   []QuizQuestion `json:"questions"`
	CreatedAt   time.Time      `json:"created_at"`
}

type QuizAnswerRequest struct {
	QuestionIndex int  `json:"question_index"`
	SelectedIndex int  `json:"selected_index"`
	TimeSpentMs   int64 `json:"time_spent_ms"`
}

type QuizAnswerResult struct {
	QuestionIndex int    `json:"question_index"`
	IsCorrect     bool   `json:"is_correct"`
	CorrectIndex  int    `json:"correct_index"`
	Explanation   string `json:"explanation,omitempty"`
}

type QuizResult struct {
	SessionID       string `json:"session_id"`
	TotalQuestions  int    `json:"total_questions"`
	CorrectAnswers  int    `json:"correct_answers"`
	IncorrectAnswers int   `json:"incorrect_answers"`
	ScorePercentage float32 `json:"score_percentage"`
	TimeSpentMs     int64  `json:"time_spent_ms"`
}

type CardSet struct {
	ID                string      `json:"id"`
	OwnerID           string      `json:"-"`
	Name              string      `json:"name"`
	Description       *string     `json:"description,omitempty"`
	CardCount         int32       `json:"card_count"`
	LearnedCount      int32       `json:"learned_count"`
	MasteryPercentage float32     `json:"mastery_percentage"`
	IsPublic          bool        `json:"is_public"`
	ViewsCount        int64       `json:"views_count"`
	ClonesCount       int64       `json:"clones_count,omitempty"`
	Tags              []string    `json:"tags,omitempty"`
	CreatedAt         time.Time   `json:"created_at"`
	Author            *AuthorInfo `json:"author,omitempty"`
}

type CardSetDetail struct {
	CardSet
	Cards []CardPreview `json:"cards"`
}

type Card struct {
	ID         string     `json:"id"`
	SetID      string     `json:"set_id"`
	Front      string     `json:"front"`
	Back       string     `json:"back"`
	ImageURL   *string    `json:"image_url,omitempty"`
	AudioURL   *string    `json:"audio_url,omitempty"`
	Status     CardStatus `json:"status"`
	ErrorCount int32      `json:"error_count"`
	LastRating CardRating `json:"last_rating"`
	NextReview *time.Time `json:"next_review,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type CardPreview struct {
	ID     string     `json:"id"`
	Front  string     `json:"front"`
	Status CardStatus `json:"status"`
}

type AuthorInfo struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Photo *string `json:"photo,omitempty"`
}

type StudySession struct {
	ID            string      `json:"id"`
	SetID         *string     `json:"set_id,omitempty"`
	UserID        string      `json:"user_id"`
	SessionType   SessionType `json:"session_type"`
	Cards         []Card      `json:"cards"`
	CurrentCardID string      `json:"current_card_id,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
}

type AnswerResult struct {
	CardID     string     `json:"card_id"`
	NewStatus  CardStatus `json:"new_status"`
	NextReview time.Time  `json:"next_review"`
	Streak     int32      `json:"streak"`
	ErrorCount int32      `json:"error_count"`
	LastRating CardRating `json:"last_rating"`
}

type SetStatistics struct {
	SetID            string      `json:"set_id"`
	TotalCards       int32       `json:"total_cards"`
	LearnedCards     int32       `json:"learned_cards"`
	LearningCards    int32       `json:"learning_cards"`
	NewCards         int32       `json:"new_cards"`
	MasteryPercentage float32     `json:"mastery_percentage"`
	StudyHistory     []StudyDay  `json:"study_history"`
}

type StudyDay struct {
	Date            string `json:"date"`
	CardsStudied    int32  `json:"cards_studied"`
	TimeSpentMinutes int32 `json:"time_spent_minutes"`
}

type UserStatistics struct {
	TotalSets           int32      `json:"total_sets"`
	TotalCards          int32      `json:"total_cards"`
	LearnedCards        int32      `json:"learned_cards"`
	CurrentStreak       int32      `json:"current_streak"`
	LongestStreak       int32      `json:"longest_streak"`
	LastStudyDate       *time.Time `json:"last_study_date,omitempty"`
	TotalStudyTimeMinutes int32    `json:"total_study_time_minutes"`
	StudyHistory        []StudyDay `json:"study_history"`
}

type SearchResultSet struct {
	Sets   []CardSet `json:"sets"`
	Offset int32     `json:"offset"`
	Count  int32     `json:"count"`
}
