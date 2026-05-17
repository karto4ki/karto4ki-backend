package services_test

import (
	"testing"

	"github.com/karto4ki/karto4ki-backend/ai-service/internal/services"
	"github.com/stretchr/testify/assert"
)

func TestDeduplicateCards_NoDuplicates(t *testing.T) {
	cards := []services.GeneratedCard{
		{Front: "Question 1", Back: "Answer 1"},
		{Front: "Question 2", Back: "Answer 2"},
		{Front: "Question 3", Back: "Answer 3"},
	}

	result := services.DeduplicateCards(cards)

	assert.Len(t, result, 3)
	assert.Equal(t, cards, result)
}

func TestDeduplicateCards_ExactDuplicates(t *testing.T) {
	cards := []services.GeneratedCard{
		{Front: "Question 1", Back: "Answer 1"},
		{Front: "Question 1", Back: "Answer 1"},
		{Front: "Question 2", Back: "Answer 2"},
		{Front: "Question 1", Back: "Answer 1"},
	}

	result := services.DeduplicateCards(cards)

	assert.Len(t, result, 2)
	assert.Equal(t, "Question 1", result[0].Front)
	assert.Equal(t, "Question 2", result[1].Front)
}

func TestDeduplicateCards_CaseInsensitive(t *testing.T) {
	cards := []services.GeneratedCard{
		{Front: "Question 1", Back: "Answer 1"},
		{Front: "QUESTION 1", Back: "ANSWER 1"},
		{Front: "question 1", Back: "answer 1"},
	}

	result := services.DeduplicateCards(cards)

	assert.Len(t, result, 1)
}

func TestDeduplicateCards_WhitespaceInsensitive(t *testing.T) {
	cards := []services.GeneratedCard{
		{Front: "Question 1", Back: "Answer 1"},
		{Front: "  Question 1  ", Back: "  Answer 1  "},
		{Front: "Question 1", Back: "Answer 1"},
	}

	result := services.DeduplicateCards(cards)

	assert.Len(t, result, 1)
}

func TestDeduplicateCards_EmptyInput(t *testing.T) {
	cards := []services.GeneratedCard{}

	result := services.DeduplicateCards(cards)

	assert.Len(t, result, 0)
}

func TestDeduplicateCards_PartialDuplicates(t *testing.T) {
	cards := []services.GeneratedCard{
		{Front: "Question 1", Back: "Answer 1"},
		{Front: "Question 1", Back: "Answer 2"}, // Same front, different back
		{Front: "Question 2", Back: "Answer 1"}, // Different front, same back
	}

	result := services.DeduplicateCards(cards)

	assert.Len(t, result, 3) // All unique combinations
}
