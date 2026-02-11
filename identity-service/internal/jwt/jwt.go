package jwt

import (
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

var (
	ErrInvalidSignInMethod = errors.New("no such signin method")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidTokenType    = errors.New("invalid token type")
	ErrInvalidAudience     = errors.New("invalid audience")
)

type Token string

type Pair struct {
	Access  Token
	Refresh Token
}

type Config struct {
	SigningMethod string

	Lifetime time.Duration
	Issuer   string
	Audience []string

	Type string

	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	SymmetricKey []byte
}

var nowFunc = func() time.Time {
	return time.Now()
}

type Claims map[string]any

func Generate(conf *Config, claims Claims) (Token, error) {
	meth := jwt.GetSigningMethod(conf.SigningMethod)
	if meth == nil {
		return "", ErrInvalidSignInMethod
	}
	if conf.Issuer != "" {
		claims["iss"] = conf.Issuer
	}
	if len(conf.Audience) != 0 {
		claims["aud"] = conf.Audience
	}
	if conf.Type != "" {
		claims["typ"] = conf.Type
	}

	now := nowFunc()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(conf.Lifetime).Unix()

	token := jwt.NewWithClaims(meth, jwt.MapClaims(claims))
	var key interface{}
	if isSymmetricMethod(meth) {
		key = conf.SymmetricKey
	} else {
		key = conf.privateKey
	}

	signed, err := token.SignedString(key)
	return Token(signed), err
}

func Parse(conf *Config, token Token) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(string(token), claims, func(token *jwt.Token) (interface{}, error) {
		method := jwt.GetSigningMethod(conf.SigningMethod)
		if isSymmetricMethod(method) {
			return conf.SymmetricKey, nil
		}
		return conf.publicKey, nil
	})

	if err != nil {
		if jwtErr, ok := err.(*jwt.ValidationError); ok && jwtErr.Errors&jwt.ValidationErrorExpired != 0 {
			return nil, ErrTokenExpired
		}
		return nil, err
	}
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}
	if conf.Issuer != "" && !claims.VerifyIssuer(conf.Issuer, true) {
		return nil, errors.New("invalid issuer")
	}

	if conf.Type != "" {
		if typ, ok := claims["typ"].(string); !ok || typ != conf.Type {
			return nil, ErrInvalidTokenType
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		claims["iat"] = int64(iat)
	}
	if exp, ok := claims["exp"].(float64); ok {
		claims["exp"] = int64(exp)
	}
	claims["jti"] = uuid.NewString()

	return claims, nil
}

func ParseWithAud(conf *Config, token Token, aud string) (jwt.MapClaims, error) {
	claims, err := Parse(conf, token)
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(aud, true) {
		return nil, errors.New("invalid audience")
	}

	return claims, nil
}

func (c *Config) RSAKeys(privateKey []byte) error {
	var err error
	c.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	c.publicKey = &c.privateKey.PublicKey
	return err
}

func isSymmetricMethod(method jwt.SigningMethod) bool {
	return strings.HasPrefix(method.Alg(), "HS")
}
