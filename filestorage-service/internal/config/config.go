package config

import (
	"log"
	"os"
	"time"

	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/spf13/viper"
)

type JWTConfig struct {
	SigningMethod string        `mapstructure:"signing_method"`
	Lifetime      time.Duration `mapstructure:"lifetime"`
	Issuer        string        `mapstructure:"issuer"`
	Audience      []string      `mapstructure:"audience"`
	KeyFilePath   string        `mapstructure:"key_file_path"`
}

func LoadJWTConfig(conf *Config) *jwt.Config {
	config := &jwt.Config{
		SigningMethod: conf.Jwt.SigningMethod,
		Lifetime:      conf.Jwt.Lifetime,
		Issuer:        conf.Jwt.Issuer,
		Audience:      conf.Jwt.Audience,
		Type:          "internal_access",
	}
	if err := config.RSAPublicOnlyKey(readKey(conf.Jwt.KeyFilePath)); err != nil {
		log.Fatal(err)
	}
	return config
}

func readKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

type S3Config struct {
	Enabled   bool   `mapstructure:"enabled"`
	Endpoint  string `mapstructure:"endpoint"`
	Bucket    string `mapstructure:"bucket"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	UseSSL    bool   `mapstructure:"use_ssl"`
	Region    string `mapstructure:"region"`
}

type Config struct {
	HTTPPort       int                 `mapstructure:"http_port"`
	StoragePath    string              `mapstructure:"storage_path"`
	MaxFileSize    int64               `mapstructure:"max_file_size"`
	AllowedTypes   []string            `mapstructure:"allowed_types"`
	ThumbnailSizes map[string]int      `mapstructure:"thumbnail_sizes"`
	Jwt            JWTConfig           `mapstructure:"jwt"`
	S3             S3Config            `mapstructure:"s3"`
}

func LoadConfig(file string) *Config {
	viper.AutomaticEnv()
	viper.BindEnv("s3.endpoint", "S3_ENDPOINT")
	viper.BindEnv("s3.access_key", "S3_ACCESS_KEY")
	viper.BindEnv("s3.secret_key", "S3_SECRET_KEY")

	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("config file not found: %v", err)
		} else {
			log.Fatalf("viper reading config failed: %s", err)
		}
	}

	config := new(Config)
	if err := viper.UnmarshalExact(&config); err != nil {
		log.Fatalf("viper config unmarshaling failed: %s", err)
	}

	return config
}
