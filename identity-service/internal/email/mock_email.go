package email

import (
	"context"
	"fmt"
)

type MockSender struct{}

func NewMockSender() *MockSender {
	return &MockSender{}
}

func (m *MockSender) SendEmail(ctx context.Context, email, message string) error {
	fmt.Printf("[MOCK EMAIL]\nTo: %s\nBody: %s\n", email, message)
	return nil
}
