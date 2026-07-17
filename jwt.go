package identity

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type TokenInfo struct {
	UserID    string
	Email     string
	ExpiresAt int64
}

func VerifyToken(tokenString string, secretKey []byte, issuer string) (*TokenInfo, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secretKey, nil
	}, jwt.WithIssuer(issuer))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	sub, _ := claims.GetSubject()
	email, _ := claims["email"].(string)
	exp, _ := claims.GetExpirationTime()

	return &TokenInfo{
		UserID:    sub,
		Email:     email,
		ExpiresAt: exp.Unix(),
	}, nil
}
