package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/karto4ki/karto4ki-backend/user-service/internal/config"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/user-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/shared/postgres"
	_ "github.com/lib/pq"
)

func main() {
	log.Println("Starting reminder worker...")

	// Load configuration
	cfg := config.LoadConfig("/app/config.yml")

	// Parse environment variables
	inactiveDays := getEnvInt("REMINDER_INACTIVE_DAYS", 3)
	batchSize := getEnvInt("REMINDER_BATCH_SIZE", 100)
	intervalHours := getEnvInt("REMINDER_INTERVAL_HOURS", 24)

	// Connect to database
	dbURL := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.DB.Host, cfg.DB.Port, cfg.DB.User, cfg.DB.Password, cfg.DB.DBName, cfg.DB.SSLMode)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	sqlDB := postgres.NewDB(db)
	userStorage := storage.NewUserStorage(sqlDB)
	userService := services.NewUserService(userStorage)

	// Initialize push service
	pushConfig := services.PushServiceConfig{
		APNsKeyPath:    os.Getenv("APNS_KEY_PATH"),
		APNsKeyID:      os.Getenv("APNS_KEY_ID"),
		APNsTeamID:     os.Getenv("APNS_TEAM_ID"),
		APNsBundleID:   os.Getenv("APNS_BUNDLE_ID"),
		APNsProduction: os.Getenv("APNS_PRODUCTION") == "true",
	}

	pushService, err := services.NewPushService(pushConfig)
	if err != nil {
		log.Printf("Warning: Push service initialization failed: %v", err)
		log.Println("Push notifications will be disabled")
	}
	defer pushService.Close()

	log.Printf("Reminder worker configured: inactive_days=%d, batch_size=%d, interval_hours=%d",
		inactiveDays, batchSize, intervalHours)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down reminder worker...")
		cancel()
	}()

	runReminders(ctx, userService, pushService, inactiveDays, batchSize, intervalHours)
}

func runReminders(ctx context.Context, userService *services.UserService, pushService *services.PushService, inactiveDays, batchSize, intervalHours int) {
	interval := time.Duration(intervalHours) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	go sendReminders(ctx, userService, pushService, inactiveDays, batchSize)

	for {
		select {
		case <-ctx.Done():
			log.Println("Reminder worker stopped")
			return
		case <-ticker.C:
			log.Printf("Running scheduled reminder check (every %d hours)", intervalHours)
			go sendReminders(ctx, userService, pushService, inactiveDays, batchSize)
		}
	}
}

func sendReminders(ctx context.Context, userService *services.UserService, pushService *services.PushService, inactiveDays, batchSize int) {
	// Calculate cutoff time (users inactive since this time)
	inactiveSince := time.Now().Add(-time.Duration(inactiveDays) * 24 * time.Hour)

	log.Printf("Finding users inactive since %s", inactiveSince.Format(time.RFC3339))

	// Get inactive users
	users, err := userService.GetInactiveUsers(ctx, inactiveSince, batchSize)
	if err != nil {
		log.Printf("Error getting inactive users: %v", err)
		return
	}

	if len(users) == 0 {
		log.Println("No inactive users found")
		return
	}

	log.Printf("Found %d inactive users to notify", len(users))

	successCount := 0
	failCount := 0

	for _, user := range users {
		tokens, err := userService.GetDeviceTokens(ctx, user.ID)
		if err != nil {
			log.Printf("Error getting device tokens for user %s: %v", user.ID, err)
			failCount++
			continue
		}

		if len(tokens) == 0 {
			log.Printf("User %s has no registered devices", user.ID)
			continue
		}

		for _, token := range tokens {
			result, err := pushService.SendReminder(ctx, user.ID.String(), token.Token, services.DeviceType(token.DeviceType))
			if err != nil || !result.Success {
				log.Printf("Failed to send reminder to user %s, device %s: %v", user.ID, token.DeviceType, err)
				failCount++
			} else {
				log.Printf("Sent reminder to user %s, device %s, message_id: %s", user.ID, token.DeviceType, result.MessageID)
				successCount++
			}
		}
	}

	log.Printf("Reminder batch completed: sent=%d, failed=%d, total_users=%d", successCount, failCount, len(users))
}

// Helper functions
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}
