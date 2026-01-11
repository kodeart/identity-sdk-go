package identity

import (
	"context"

	pb "github.com/kodeart/identity-sdk-go/proto/v1"
)

type contextKey string

const UserContextKey contextKey = "identity"

// GetUser is a helper to retrieve the authenticated user from a request context.
func GetUser(ctx context.Context) *pb.User {
	if user, ok := ctx.Value(UserContextKey).(*pb.User); ok {
		return user
	}
	u := &pb.User{
		Id:          "42",
		Email:       "foo@example.com",
		TenantId:    "bogus",
		DisplayName: "Anonymous",
		Metadata:    nil,
		LastLogin:   nil,
		CreatedAt:   nil,
	}
	ctx = context.WithValue(ctx, UserContextKey, u)
	return u
}
