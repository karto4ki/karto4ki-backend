package services

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
	"github.com/sideshow/apns2/payload"
)

var (
	ErrInvalidDeviceToken = errors.New("invalid device token")
	ErrPushFailed         = errors.New("failed to send push notification")
	ErrInvalidCredentials = errors.New("invalid push credentials")
)

// DeviceType represents the type of device
type DeviceType string

const (
	DeviceiOS   DeviceType = "ios"
	DeviceAndroid DeviceType = "android"
)

// PushNotification represents a push notification request
type PushNotification struct {
	UserID      string                 `json:"user_id"`
	DeviceToken string                 `json:"device_token"`
	DeviceType  DeviceType             `json:"device_type"`
	Title       string                 `json:"title"`
	Body        string                 `json:"body"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Badge       *int                   `json:"badge,omitempty"`
	Sound       string                 `json:"sound,omitempty"`
}

// PushResult represents the result of a push notification
type PushResult struct {
	Success   bool   `json:"success"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// NotificationType represents the type of notification
type NotificationType string

const (
	NotificationTypeReminder      NotificationType = "reminder"
	NotificationTypeAchievement   NotificationType = "achievement"
	NotificationTypeSetCreated    NotificationType = "set_created"
	NotificationTypeStreakWarning NotificationType = "streak_warning"
)

// PushService handles push notifications for iOS
type PushService struct {
	apnsClient   *apns2.Client
	production   bool
	bundleID     string
}

// PushServiceConfig holds configuration for push service
type PushServiceConfig struct {
	APNsKeyPath    string `yaml:"apns_key_path"`
	APNsKeyID      string `yaml:"apns_key_id"`
	APNsTeamID     string `yaml:"apns_team_id"`
	APNsBundleID   string `yaml:"apns_bundle_id"`
	APNsProduction bool   `yaml:"apns_production"`
}

// NewPushService creates a new push notification service
func NewPushService(cfg PushServiceConfig) (*PushService, error) {
	service := &PushService{
		production: cfg.APNsProduction,
		bundleID:   cfg.APNsBundleID,
	}

	// Initialize APNs (iOS)
	if cfg.APNsKeyPath != "" && cfg.APNsKeyID != "" && cfg.APNsTeamID != "" {
		authKey, err := token.AuthKeyFromFile(cfg.APNsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load APNs key: %w", err)
		}

		tokenKey := &token.Token{
			AuthKey: authKey,
			KeyID:   cfg.APNsKeyID,
			TeamID:  cfg.APNsTeamID,
		}

		client := &apns2.Client{
			Token: tokenKey,
			HTTPClient: &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSHandshakeTimeout: 10 * time.Second,
					Proxy:               http.ProxyFromEnvironment,
				},
			},
			Host: apns2.HostDevelopment,
		}

		if cfg.APNsProduction {
			client.Host = apns2.HostProduction
		}

		service.apnsClient = client
	}

	return service, nil
}

// Send sends a push notification to the specified device
func (s *PushService) Send(ctx context.Context, notif *PushNotification) (*PushResult, error) {
	if notif.DeviceToken == "" {
		return &PushResult{Success: false, Error: ErrInvalidDeviceToken.Error()}, ErrInvalidDeviceToken
	}

	if notif.DeviceType != DeviceiOS {
		return &PushResult{Success: false, Error: "unsupported device type"}, fmt.Errorf("unsupported device type: %s", notif.DeviceType)
	}

	return s.sendAPNs(ctx, notif)
}

// sendAPNs sends push notification to iOS device
func (s *PushService) sendAPNs(ctx context.Context, notif *PushNotification) (*PushResult, error) {
	if s.apnsClient == nil {
		return &PushResult{Success: false, Error: "APNs client not configured"}, ErrInvalidCredentials
	}

	// Validate device token (should be 64 hex characters for iOS)
	if !ValidateDeviceToken(notif.DeviceToken, DeviceiOS) {
		return &PushResult{Success: false, Error: "invalid iOS device token format"}, ErrInvalidDeviceToken
	}

	// Build payload
	notification := &apns2.Notification{
		DeviceToken: notif.DeviceToken,
		Topic:       s.bundleID,
		Payload:     s.buildAPNsPayload(notif),
	}

	// Set expiration
	if deadline, ok := ctx.Deadline(); ok {
		notification.Expiration = deadline
	} else {
		notification.Expiration = time.Now().Add(24 * time.Hour)
	}

	// Send notification
	res, err := s.apnsClient.PushWithContext(ctx, notification)
	if err != nil {
		return &PushResult{Success: false, Error: err.Error()}, fmt.Errorf("%w: %v", ErrPushFailed, err)
	}

	if res.StatusCode != http.StatusOK {
		return &PushResult{
			Success: false,
			Error:   fmt.Sprintf("APNs error: %d - %s", res.StatusCode, res.Reason),
		}, fmt.Errorf("%w: status=%d, reason=%s", ErrPushFailed, res.StatusCode, res.Reason)
	}

	return &PushResult{
		Success:   true,
		MessageID: res.ApnsID,
	}, nil
}

// buildAPNsPayload creates the APNs payload
func (s *PushService) buildAPNsPayload(notif *PushNotification) *payload.Payload {
	p := payload.NewPayload()

	// Alert
	p.AlertTitle(notif.Title)
	p.AlertBody(notif.Body)

	// Sound
	if notif.Sound != "" {
		p.Sound(notif.Sound)
	} else {
		p.Sound("default")
	}

	// Badge
	if notif.Badge != nil {
		p.Badge(*notif.Badge)
	}

	// Custom data
	for key, value := range notif.Data {
		p.Custom(key, value)
	}

	return p
}

// SendBatch sends push notifications to multiple devices
func (s *PushService) SendBatch(ctx context.Context, notifications []*PushNotification) []*PushResult {
	results := make([]*PushResult, len(notifications))
	var wg sync.WaitGroup

	for i, notif := range notifications {
		wg.Add(1)
		go func(index int, n *PushNotification) {
			defer wg.Done()
			result, _ := s.Send(ctx, n)
			results[index] = result
		}(i, notif)
	}

	wg.Wait()
	return results
}

// SendReminder sends a study reminder notification
func (s *PushService) SendReminder(ctx context.Context, userID, deviceToken string, deviceType DeviceType) (*PushResult, error) {
	return s.Send(ctx, &PushNotification{
		UserID:      userID,
		DeviceToken: deviceToken,
		DeviceType:  DeviceiOS,
		Title:       "Пора учиться! 📚",
		Body:        "Не забудь повторить карточки сегодня",
		Data: map[string]interface{}{
			"type":      string(NotificationTypeReminder),
			"screen":    "home",
			"timestamp": time.Now().Unix(),
		},
		Sound: "default",
	})
}

// SendStreakWarning sends a streak warning notification
func (s *PushService) SendStreakWarning(ctx context.Context, userID, deviceToken string, deviceType DeviceType, streak int) (*PushResult, error) {
	return s.Send(ctx, &PushNotification{
		UserID:      userID,
		DeviceToken: deviceToken,
		DeviceType:  DeviceiOS,
		Title:       "🔥 Серия под угрозой!",
		Body:        fmt.Sprintf("Твоя серия %d дней. Зайди в приложение, чтобы не потерять!", streak),
		Data: map[string]interface{}{
			"type":      string(NotificationTypeStreakWarning),
			"screen":    "streak",
			"streak":    streak,
			"timestamp": time.Now().Unix(),
		},
		Sound: "default",
	})
}

// SendAchievement sends an achievement notification
func (s *PushService) SendAchievement(ctx context.Context, userID, deviceToken string, deviceType DeviceType, achievementName string) (*PushResult, error) {
	return s.Send(ctx, &PushNotification{
		UserID:      userID,
		DeviceToken: deviceToken,
		DeviceType:  DeviceiOS,
		Title:       "🏆 Достижение!",
		Body:        fmt.Sprintf("Ты получил достижение: %s", achievementName),
		Data: map[string]interface{}{
			"type":        string(NotificationTypeAchievement),
			"screen":      "achievements",
			"achievement": achievementName,
			"timestamp":   time.Now().Unix(),
		},
		Sound: "achievement.caf",
	})
}

// ValidateDeviceToken checks if device token format is valid
func ValidateDeviceToken(token string, deviceType DeviceType) bool {
	if token == "" {
		return false
	}

	// iOS tokens are 64 hex characters
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// Close closes the push service connections
func (s *PushService) Close() error {
	// No explicit cleanup needed for current implementation
	return nil
}
