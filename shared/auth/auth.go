package auth

import (
	"context"
	"log"
	"strings"

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
		headerName := conf.DefaultHeader
		if headerName == "" {
			headerName = headerAuthorization
		}

		authHeader := c.Request.Header.Get(headerName)
		if authHeader == "" {
			log.Printf("[JWT] Unauthorized: missing %s header", headerName)
			restapi.SendUnautorized(c)
			c.Abort()
			return
		}

		token := authHeader
		const prefix = "Bearer "
		if len(authHeader) > len(prefix) && strings.EqualFold(authHeader[:len(prefix)], prefix) {
			token = authHeader[len(prefix):]
		}
		token = strings.TrimSpace(token)
		if token == "" {
			log.Printf("[JWT] Unauthorized: empty token after trimming")
			restapi.SendUnautorized(c)
			c.Abort()
			return
		}

		log.Printf("[JWT] Token received: %s...", token[:min(50, len(token))])

		var claims jwt.Claims
		var err error
		if conf.Aud != "" {
			mapClaims, parseErr := jwt.ParseWithAud(conf.Conf, jwt.Token(token), conf.Aud)
			if parseErr != nil {
				err = parseErr
			} else {
				claims = jwt.Claims(mapClaims)
			}
		} else {
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
		ctx := context.WithValue(c.Request.Context(), keyClaims, Claims(claims))
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
