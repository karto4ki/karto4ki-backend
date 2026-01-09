package jwt

import (
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

	publicKey  *rsa.PublicKey  // Used for asymmetric signing
	privateKey *rsa.PrivateKey // Used for asymmetric signing

	SymmetricKey []byte // Used for symmetric signing
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

	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(conf.Lifetime).Unix()

	token := jwt.NewWithClaims(meth, jwt.MapClaims(claims))
	var key interface{}
	if isSymmetricMethod(meth) {
		if len(conf.SymmetricKey) == 0 {
			return "", errors.New("symmetric key required for HMAC algorithm")
		}
		key = conf.SymmetricKey
	} else {
		if conf.privateKey == nil {
			return "", errors.New("private key required for RSA/ECDSA algorithm")
		}
		key = conf.privateKey
	}

	signed, err := token.SignedString(key)
	return Token(signed), err
}

func Parse(conf *Config, token Token) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(string(token), claims, func(token *jwt.Token) (interface{}, error) {
		method := jwt.GetSigningMethod(conf.SigningMethod)
		if method == nil {
			return nil, ErrInvalidSignInMethod
		}

		if token.Method.Alg() != method.Alg() {
			return nil, ErrInvalidSignInMethod
		}

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return conf.SymmetricKey, nil
		} else {
			return conf.publicKey, nil
		}
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if !parsed.Valid {
			return nil, ErrInvalidToken
		}
		if conf.Type != "" {
			if typ, ok := claims["typ"].(string); !ok || typ != conf.Type {
				return nil, ErrInvalidTokenType
			}
		}
		return nil, ErrInvalidToken
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

func isSymmetricMethod(method jwt.SigningMethod) bool {
	return strings.HasPrefix(method.Alg(), "HS")
}
