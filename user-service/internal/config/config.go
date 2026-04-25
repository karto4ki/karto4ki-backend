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

type Config struct {
	DB struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		DBName   string `mapstructure:"dbname"`
		SSLMode  string `mapstructure:"sslmode"`
	} `mapstructure:"db"`
	Jwt      JWTConfig `mapstructure:"jwt"`
	HTTPPort int       `mapstructure:"http_port"`
	GRPCPort int       `mapstructure:"grpc_port"`
}

func LoadConfig(file string) *Config {
	viper.AutomaticEnv()

	viper.MustBindEnv("db.dsn", "DB_DSN")
	viper.BindEnv("server.port", "SERVER_PORT")

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
