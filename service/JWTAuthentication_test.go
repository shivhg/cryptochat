package service

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"gotest.tools/assert"
	"testing"
)

func TestGenerateJwtToken(t *testing.T) {
	var jwtService = JWTAuthService()
	name := "shivhg@gmail.com"
	jwtToken := jwtService.GenerateToken(name)

	token, _ := jwtService.ValidateToken(jwtToken)
	claims, _ := token.Claims.(jwt.MapClaims)
	assert.Equal(t, claims["name"], name)
}

func TestValidatingToken(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.u1riaD1rW97opCoAuRCTy4w58Br-Zk-bh7vLiRIsrpU"

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte{}, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}
}
