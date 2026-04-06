package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/email"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/handlers"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/jwt"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/restapi"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/services"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/storage"
	"github.com/karto4ki/karto4ki-backend/identity-service/internal/userservice"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type JWTConfig struct {
	SigningMethod string        `mapstructure:"signing_method"`
	Lifetime      time.Duration `mapstructure:"lifetime"`
	Issuer        string        `mapstructure:"issuer"`
	Audience      []string      `mapstructure:"audience"`
	KeyFilePath   string        `mapstructure:"key_file_path"`
}

type Config struct {
	AccessToken   JWTConfig `mapstructure:"access_token"`
	RefreshToken  JWTConfig `mapstructure:"refresh_token"`
	InternalToken JWTConfig `mapstructure:"internal_token"`

	InvalidatedTokenStorage struct {
		Exp time.Duration `mapstructure:"exp"`
	} `mapstructure:"invalidated_token_storage"`

	UserService struct {
		GrpcAddr string `mapstructure:"grpc_addr"`
	} `mapstructure:"userservice"`

	GRPCService struct {
		Port int `mapstructure:"port"`
	} `mapstructure:"grpc_service"`

	Redis struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	SignInMeta struct {
		Lifetime time.Duration `mapstructure:"lifetime"`
	} `mapstructure:"signin_meta"`

	Idempotency struct {
		DataExp time.Duration `mapstructure:"data_exp"`
		LockTTL time.Duration `mapstructure:"lock_ttl"` // Добавлено
	} `mapstructure:"idempotency"`

	EmailCode struct {
		SendFrequency time.Duration `mapstructure:"send_frequency"`
	} `mapstructure:"email_code"`

	Email struct {
		Email  string `mapstructure:"email"`
		ApiKey string `mapstructure:"api_key"`
	} `mapstructure:"email"`

	OAuth struct {
		GoogleClientID string `mapstructure:"google_client_id"`
		AppleClientID  string `mapstructure:"apple_client_id"`
	} `mapstructure:"oauth"`

	SignUp struct {
		CodeTTL time.Duration `mapstructure:"code_ttl"`
	} `mapstructure:"signup"`
}

func loadConfig(file string) *Config {
	viper.AutomaticEnv()
	viper.BindEnv("email.email", "SMTP_EMAIL")
	viper.BindEnv("email.api_key", "SMTP_APIKEY")

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

var conf *Config = loadConfig("/app/config.yml")

func main() {
	rdb := connectRedis()
	defer rdb.Close()

	email := createEmailSender()
	usersClient, closeGrpc := createUsersClient()
	defer closeGrpc()

	accessTokenConfig := loadAccessTokenConfig()
	refreshTokenConfig := loadRefreshTokenConfig()
	internalTokenConfig := loadInternalTokenConfig()

	idempotencyStorage := createIdempotencyStorage(rdb)
	authMetaStorage := createAuthMetaStorage(rdb)
	invalidatedTokenStorage := createInvalidatedTokenStorage(rdb)

	sendCodeService := createSendCodeService(email, *authMetaStorage, usersClient)
	verifyCodeService := createVerifyCodeService(*authMetaStorage)
	signInService := services.NewSignInService(authMetaStorage, accessTokenConfig, refreshTokenConfig)
	refreshService := services.NewRefreshJWTService(accessTokenConfig, refreshTokenConfig, invalidatedTokenStorage)
	signOutService := services.NewSignOutService(refreshTokenConfig, invalidatedTokenStorage)
	signUpService := services.NewSignUpService(authMetaStorage, usersClient, accessTokenConfig, refreshTokenConfig)
	googleAuthService := services.NewGoogleAuthService(accessTokenConfig, refreshTokenConfig, usersClient, conf.OAuth.GoogleClientID)
	appleAuthService := services.NewAppleAuthService(accessTokenConfig, refreshTokenConfig, usersClient, conf.OAuth.AppleClientID)
	identityService := services.NewAuthService(accessTokenConfig, internalTokenConfig)
	idempotencyConf := services.MiddlewareConfig{
		Storage:    idempotencyStorage,
		LockTTL:    conf.Idempotency.LockTTL,
		ResultTTL:  conf.Idempotency.DataExp,
		RetryCount: 3,
		RetryDelay: 100 * time.Millisecond,
	}

	grpcListener, err := net.Listen("tcp", ":"+strconv.Itoa(conf.GRPCService.Port))
	if err != nil {
		log.Fatalf("Listening TCP failed: %s", err)
	}

	grpcServer := grpc.NewServer()

	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	r := gin.New()

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, restapi.ErrorResponse{
			ErrorType:    restapi.ErrTypeNotFound,
			ErrorMessage: "No such endpoint. Make sure that you use correct route and HTTP method.",
		})
	})

	r.Use(gin.Logger())

	r.Group("/v1.0").
		Use(services.NewMiddleware(idempotencyConf)).
		POST("/signin/send-email-code", handlers.SignInSendCode(sendCodeService)).
		POST("/signin", handlers.SignIn(signInService)).
		POST("/refresh-token", handlers.RefreshJWT(refreshService)).
		POST("/signin/oath/google", handlers.GoogleAuth(googleAuthService)).
		POST("/signin/oath/apple", handlers.AppleAuth(appleAuthService)).
		POST("/signup", handlers.SignUp(signUpService)).
		POST("/verify-code", handlers.VerifyCode(verifyCodeService))
	r.PUT("/sign-out", handlers.SignOut(signOutService))
	r.GET("/v1.0/identity", handlers.NewIdentityHandler(identityService))

	r.Run(":5000")
}

func createEmailSender() email.EmailSender {
	if os.Getenv("SMTP_HOST") == "" {
		return email.NewMockSender()
	}

	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if port == 0 {
		port = 587
	}

	config := &email.SMTPConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
	}

	return email.NewSMTPSender(config)
}

func createInvalidatedTokenStorage(redisClient *redis.Client) *storage.RevokeStorage {
	conf := conf.InvalidatedTokenStorage.Exp
	return storage.NewRevokeStorage(redisClient, conf)
}

func createSignUpStorage(redisClient *redis.Client) *storage.AuthStorage {
	conf := conf.SignUp.CodeTTL
	return storage.NewAuthStorage(redisClient, conf)
}

func loadAccessTokenConfig() *jwt.Config {
	return &jwt.Config{
		SigningMethod: conf.AccessToken.SigningMethod,
		Lifetime:      conf.AccessToken.Lifetime,
		Issuer:        conf.AccessToken.Issuer,
		Audience:      conf.AccessToken.Audience,
		Type:          "access",
		SymmetricKey:  readKey(conf.AccessToken.KeyFilePath),
	}
}

func loadRefreshTokenConfig() *jwt.Config {
	return &jwt.Config{
		SigningMethod: conf.RefreshToken.SigningMethod,
		Lifetime:      conf.RefreshToken.Lifetime,
		Issuer:        conf.RefreshToken.Issuer,
		Audience:      conf.RefreshToken.Audience,
		Type:          "refresh",
		SymmetricKey:  readKey(conf.RefreshToken.KeyFilePath),
	}
}

func loadInternalTokenConfig() *jwt.Config {
	res := &jwt.Config{
		SigningMethod: conf.InternalToken.SigningMethod,
		Lifetime:      conf.InternalToken.Lifetime,
		Issuer:        conf.InternalToken.Issuer,
		Audience:      conf.InternalToken.Audience,
		Type:          "internal_access",
	}
	res.RSAKeys(readKey(conf.InternalToken.KeyFilePath))
	return res
}

func createUsersClient() (client userservice.UserServiceClient, closeFunc func() error) {
	addr := conf.UserService.GrpcAddr
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	return userservice.NewUserServiceClient(conn), conn.Close
}

func connectRedis() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     conf.Redis.Addr,
		Password: conf.Redis.Password,
		DB:       conf.Redis.DB,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("redis connection establishing failed: %s", err)
	}
	log.Println("redis connection established")
	return client
}

func createAuthMetaStorage(redisClient *redis.Client) *storage.AuthStorage {
	config := conf.SignInMeta.Lifetime
	return storage.NewAuthStorage(redisClient, config)
}

func createIdempotencyStorage(redisClient *redis.Client) services.IdempotencyStorage {
	idempotencyConf := conf.Idempotency.DataExp
	return storage.NewRedisIdempotencyStorage(redisClient, idempotencyConf)
}

func createSendCodeService(email email.EmailSender, storage storage.AuthStorage,
	users userservice.UserServiceClient) *services.SendCodeService {
	config := conf.EmailCode.SendFrequency
	return services.NewSendCodeService(&config, storage, email, users)
}

func createVerifyCodeService(storage storage.AuthStorage) *services.AuthVerifyService {
	return services.NewAuthVerifyService(&storage)
}

func readKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return key
}
