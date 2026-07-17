package middleware

import (
	"context"
	"strings"

	"github.com/kodeart/identity-sdk-go"
	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func AuthGRPCInterceptor(secretKey []byte, issuer string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}
		values := md.Get("authorization")
		if len(values) == 0 {
			return handler(ctx, req)
		}
		auth := values[0]
		if !strings.HasPrefix(auth, "Bearer ") {
			return handler(ctx, req)
		}
		token := strings.TrimPrefix(auth, "Bearer ")

		tokenInfo, err := identity.VerifyToken(token, secretKey, issuer)
		if err != nil {
			log.Warn().Err(err).Msg("jwt auth interceptor: invalid token")
			return handler(ctx, req)
		}

		ctx = context.WithValue(ctx, identity.UserContextKey, &pb.ValidateSessionResponse{
			AccessToken: token,
			UserId:      tokenInfo.UserID,
			ExpiresAt:   tokenInfo.ExpiresAt,
		})
		return handler(ctx, req)
	}
}
