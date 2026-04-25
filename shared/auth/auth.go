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
		log.Println(token)
		// token, ok := strings.CutPrefix(header, "Bearer ")
		// if !ok {
		// 	log.Println("Unautorized because of invalid header")
		// 	restapi.SendUnautorized(c)
		// 	c.Abort()
		// 	return
		// }
		var ctx context.Context

		if conf.Aud != "" {
			claims, err := jwt.ParseWithAud(conf.Conf, jwt.Token(token), conf.Aud)
			if err != nil {
				log.Printf("Unauthorized: %s", err)
				restapi.SendUnautorized(c)
				c.Abort()
				return
			}
			ctx = context.WithValue(
				c.Request.Context(),
				keyClaims, Claims(claims),
			)
		} else {
			claims, err := jwt.Parse(conf.Conf, jwt.Token(token))
			if err != nil {
				log.Printf("Unauthorized: %s", err)
				restapi.SendUnautorized(c)
				c.Abort()
				return
			}
			ctx = context.WithValue(
				c.Request.Context(),
				keyClaims, Claims(claims),
			)
		}

		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

func GetClaims(ctx context.Context) Claims {
	if val := ctx.Value(keyClaims); val != nil {
		return val.(Claims)
	}
	return nil
}
