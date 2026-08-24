package identity

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

func VerifyToken(tokenString string, secretKey []byte, issuer string) (*pb.SessionUser, error) {
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

	userJSON, err := json.Marshal(claims["user"])
	if err != nil {
		return nil, fmt.Errorf("invalid token claims")
	}
	var su pb.SessionUser
	if err := json.Unmarshal(userJSON, &su); err != nil {
		return nil, fmt.Errorf("invalid token claims")
	}
	return &su, nil
}
