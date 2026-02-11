package email

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPConfig struct {
	Host     string // smtp.gmail.com
	Port     int    // 587
	Username string // ваш email
	Password string // пароль приложения
	From     string // отправитель
}

type EmailSender interface {
	SendEmail(ctx context.Context, email, message string) error
}

type SMTPSender struct {
	config *SMTPConfig
	auth   smtp.Auth
}

func NewSMTPSender(config *SMTPConfig) *SMTPSender {
	auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)
	return &SMTPSender{
		config: config,
		auth:   auth,
	}
}

func (s *SMTPSender) SendEmail(ctx context.Context, email, message string) error {
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Content-Type: text/plain; charset=\"UTF-8\"\r\n"+
		"\r\n"+
		"%s",
		s.config.From, email, message)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	return smtp.SendMail(addr, s.auth, s.config.From, []string{email}, []byte(msg))
}
