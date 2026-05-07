package config

import (
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/spf13/viper"
	"log"
	"os"
	"time"
)

type Config struct {
	Jwt JWTConfig `mapstructure:"jwt"`

	Redis struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	HTTPPort int `mapstructure:"http_port"`

	GRPCService struct {
		Port int `mapstructure:"port"`
	} `mapstructure:"grpc_service"`

	Idempotency struct {
		DataExp time.Duration `mapstructure:"data_exp"`
	} `mapstructure:"idempotency"`

	Upload struct {
		FileSizeLimit int64 `mapstructure:"file_size_limit"`
	} `mapstructure:"upload"`

	MultipartUpload struct {
		MinFileSize int64 `mapstructure:"min_file_size"`
		MaxPartSize int64 `mapstructure:"max_part_size"`
	} `mapstructure:"multipart_upload"`

	S3 struct {
		Bucket    string `mapstructure:"bucket"`
		URLPrefix string `mapstructure:"url_prefix"`
		Endpoint  string `mapstructure:"endpoint"`
		Region    string `mapstructure:"region"`
	} `mapstructure:"s3"`

	AWS struct {
		AccessKeyID     string `mapstructure:"access_key_id"`
		SecretAccessKey string `mapstructure:"secret_access_key"`
		Region          string `mapstructure:"region"`
		EndpointURL     string `mapstructure:"endpoint_url"`
	} `mapstructure:"aws"`
}

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

func LoadConfig(file string) *Config {
	viper.AutomaticEnv()

	viper.BindEnv("s3.bucket", "FILE_STORAGE_S3_BUCKET")
	viper.BindEnv("s3.url_prefix", "FILE_STORAGE_S3_URL_PREFIX")
	viper.BindEnv("s3.endpoint", "FILE_STORAGE_S3_ENDPOINT")

	viper.BindEnv("aws.access_key_id", "FILE_STORAGE_AWS_ACCESS_KEY_ID")
	viper.BindEnv("aws.secret_access_key", "FILE_STORAGE_AWS_SECRET_ACCESS_KEY")
	viper.BindEnv("aws.region", "FILE_STORAGE_AWS_REGION")
	viper.BindEnv("aws.endpoint_url", "FILE_STORAGE_AWS_ENDPOINT_URL")

	viper.BindEnv("redis.addr", "FILE_STORAGE_REDIS_ADDR")
	viper.BindEnv("redis.password", "FILE_STORAGE_REDIS_PASSWORD")

	viper.SetConfigFile(file)

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("viper reading config failed: %s", err)
	}

	conf := new(Config)
	if err := viper.UnmarshalExact(&conf); err != nil {
		log.Fatalf("viper config unmarshalling failed: %s", err)
	}

	return conf
}
