package auth

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/karto4ki/karto4ki-backend/shared/jwt"
	"github.com/karto4ki/karto4ki-backend/shared/restapi"
)

const (
	headerAuthorization = "Authorization"
)

// It is a copy of jwt claim names
const (
	ClaimName     = "name"
	ClaimUsername = "username"
	ClaimId       = "sub"
)

type keyClaimsType int

var keyClaims = keyClaimsType(69)

// GetClaimsKey returns the key used for storing claims in context
func GetClaimsKey() keyClaimsType {
	return keyClaims
}

type Claims map[string]any

type JWTConfig struct {
	Conf          *jwt.Config
	Aud           string
	DefaultHeader string
}

func NewJWT(conf *JWTConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var headerName string
		if conf.DefaultHeader != "" {
			headerName = conf.DefaultHeader
		} else {
			headerName = headerAuthorization
		}

		token := c.Request.Header.Get(headerName)
		if token == "" {
			log.Printf("[JWT] Unauthorized: missing %s header", headerName)
			restapi.SendUnautorized(c)
			c.Abort()
			return
		}

		log.Printf("[JWT] Token received on %s: %s...", headerName, token[:min(50, len(token))])

		var claims jwt.Claims
		var err error

		if conf.Aud != "" {
			log.Printf("[JWT] Validating with audience: %s", conf.Aud)
			mapClaims, parseErr := jwt.ParseWithAud(conf.Conf, jwt.Token(token), conf.Aud)
			if parseErr != nil {
				err = parseErr
			} else {
				claims = jwt.Claims(mapClaims)
			}
		} else {
			log.Printf("[JWT] Validating without audience")
			mapClaims, parseErr := jwt.Parse(conf.Conf, jwt.Token(token))
			if parseErr != nil {
				err = parseErr
			} else {
				claims = jwt.Claims(mapClaims)
			}
		}

		if err != nil {
			log.Printf("[JWT] Unauthorized: %v", err)
			restapi.SendUnautorized(c)
			c.Abort()
			return
		}

		log.Printf("[JWT] Token validated successfully for user: %v", claims["sub"])

		ctx := context.WithValue(
			c.Request.Context(),
			keyClaims, Claims(claims),
		)
		c.Request = c.Request.WithContext(ctx)

		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}

		c.Next()
	}
}

func GetClaims(ctx context.Context) Claims {
	if val := ctx.Value(keyClaims); val != nil {
		return val.(Claims)
	}
	return nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
