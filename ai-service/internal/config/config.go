package config

import (
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	HTTPPort int `yaml:"http_port"`

	LLM LLMConfig `yaml:"llm"`

	Generation GenerationConfig `yaml:"generation"`

	PDF PDFConfig `yaml:"pdf"`

	Vision VisionConfig `yaml:"vision"`

	CardService CardServiceConfig `yaml:"card_service"`

	Redis RedisConfig `yaml:"redis"`

	Kafka KafkaConfig `yaml:"kafka"`

	JWT JWTConfig `yaml:"jwt"`
}

type LLMConfig struct {
	Provider string `yaml:"provider"`
	APIKey   string `yaml:"api_key"`
	BaseURL  string `yaml:"base_url"`
	Model    string `yaml:"model"`
	Vision   bool   `yaml:"vision"` // Support for multimodal models
}

type GenerationConfig struct {
	DefaultCardCount int    `yaml:"default_card_count"`
	MaxCardCount     int    `yaml:"max_card_count"`
	MinCardCount     int    `yaml:"min_card_count"`
	DefaultDifficulty string `yaml:"default_difficulty"`
	DefaultLanguage  string `yaml:"default_language"`
}

type PDFConfig struct {
	MaxFileSizeMB   int `yaml:"max_file_size_mb"`
	MinTextLength   int `yaml:"min_text_length"`
}

type VisionConfig struct {
	MaxFileSizeMB    int      `yaml:"max_file_size_mb"`
	MinTextLength    int      `yaml:"min_text_length"`
	SupportedFormats []string `yaml:"supported_formats"`
	DefaultLanguage  string   `yaml:"default_language"`
}

type CardServiceConfig struct {
	GRPCAddress string        `yaml:"grpc_address"`
	Timeout     time.Duration `yaml:"timeout"`
}

type RedisConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Password     string `yaml:"password"`
	DB           int    `yaml:"db"`
	TaskTTLHours int    `yaml:"task_ttl_hours"`
}

type KafkaConfig struct {
	Brokers       []string            `yaml:"brokers"`
	ConsumerGroup string              `yaml:"consumer_group"`
	Topics        KafkaTopicsConfig   `yaml:"topics"`
	Consumer      KafkaConsumerConfig `yaml:"consumer"`
	Producer      KafkaProducerConfig `yaml:"producer"`
}

type KafkaTopicsConfig struct {
	GenerationTasks  string `yaml:"generation_tasks"`
	GenerationEvents string `yaml:"generation_events"`
}

type KafkaConsumerConfig struct {
	Concurrency  int `yaml:"concurrency"`
	MaxRetries   int `yaml:"max_retries"`
	RetryDelayMs int `yaml:"retry_delay_ms"`
}

type KafkaProducerConfig struct {
	RequiredAcks int `yaml:"required_acks"`
	TimeoutMs    int `yaml:"timeout_ms"`
}

type JWTConfig struct {
	SigningMethod string   `yaml:"signing_method"`
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	KeyFilePath   string   `yaml:"key_file_path"`
}

func LoadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	if apiKey := os.Getenv("LLM_API_KEY"); apiKey != "" {
		cfg.LLM.APIKey = apiKey
	}
	if baseURL := os.Getenv("LLM_BASE_URL"); baseURL != "" {
		cfg.LLM.BaseURL = baseURL
	}
	if model := os.Getenv("LLM_MODEL"); model != "" {
		cfg.LLM.Model = model
	}

	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8083
	}
	if cfg.LLM.Model == "" {
		cfg.LLM.Model = "gpt-4o-mini"
	}
	if cfg.Generation.DefaultCardCount == 0 {
		cfg.Generation.DefaultCardCount = 5
	}
	if cfg.Generation.MaxCardCount == 0 {
		cfg.Generation.MaxCardCount = 150
	}
	if cfg.Generation.MinCardCount == 0 {
		cfg.Generation.MinCardCount = 1
	}
	if cfg.Generation.DefaultDifficulty == "" {
		cfg.Generation.DefaultDifficulty = "intermediate"
	}
	if cfg.Generation.DefaultLanguage == "" {
		cfg.Generation.DefaultLanguage = "ru"
	}
	if cfg.PDF.MaxFileSizeMB == 0 {
		cfg.PDF.MaxFileSizeMB = 10
	}
	if cfg.PDF.MinTextLength == 0 {
		cfg.PDF.MinTextLength = 100
	}

	// Vision defaults
	if cfg.Vision.MaxFileSizeMB == 0 {
		cfg.Vision.MaxFileSizeMB = 10
	}
	if cfg.Vision.MinTextLength == 0 {
		cfg.Vision.MinTextLength = 20
	}
	if len(cfg.Vision.SupportedFormats) == 0 {
		cfg.Vision.SupportedFormats = []string{"image/jpeg", "image/png", "image/webp"}
	}
	if cfg.Vision.DefaultLanguage == "" {
		cfg.Vision.DefaultLanguage = "ru"
	}

	if cfg.CardService.Timeout == 0 {
		cfg.CardService.Timeout = 30 * time.Second
	}
	if cfg.Redis.TaskTTLHours == 0 {
		cfg.Redis.TaskTTLHours = 24
	}

	// Kafka defaults
	if len(cfg.Kafka.Brokers) == 0 {
		cfg.Kafka.Brokers = []string{"kafka:29092"}
	}
	if cfg.Kafka.ConsumerGroup == "" {
		cfg.Kafka.ConsumerGroup = "ai-workers"
	}
	if cfg.Kafka.Topics.GenerationTasks == "" {
		cfg.Kafka.Topics.GenerationTasks = "ai.generation.tasks"
	}
	if cfg.Kafka.Topics.GenerationEvents == "" {
		cfg.Kafka.Topics.GenerationEvents = "ai.generation.events"
	}
	if cfg.Kafka.Consumer.Concurrency == 0 {
		cfg.Kafka.Consumer.Concurrency = 3
	}
	if cfg.Kafka.Consumer.MaxRetries == 0 {
		cfg.Kafka.Consumer.MaxRetries = 3
	}
	if cfg.Kafka.Consumer.RetryDelayMs == 0 {
		cfg.Kafka.Consumer.RetryDelayMs = 1000
	}
	if cfg.Kafka.Producer.RequiredAcks == 0 {
		cfg.Kafka.Producer.RequiredAcks = 1
	}
	if cfg.Kafka.Producer.TimeoutMs == 0 {
		cfg.Kafka.Producer.TimeoutMs = 5000
	}

	return &cfg
}
