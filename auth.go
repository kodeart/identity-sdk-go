package identity

import (
	"context"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

func (c *Client) SignInWithCredentials(ctx context.Context, email, password string) (*pb.SignInResponse, error) {
	return c.svcAuth.SignInWithCredentials(ctx, &pb.SignInWithCredentialsRequest{
		Email:    email,
		Password: password,
	})
}

func (c *Client) SignInWithProvider(ctx context.Context, providerToken string) (*pb.SignInResponse, error) {
	return c.svcAuth.SignInWithProvider(ctx, &pb.SignInProviderRequest{
		ProviderToken: providerToken,
	})
}

func (c *Client) ValidateSession(ctx context.Context, token string) (*pb.ValidateSessionResponse, error) {
	return c.svcAuth.ValidateSession(ctx, &pb.ValidateSessionRequest{AccessToken: token})
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*pb.RefreshTokenResponse, error) {
	return c.svcAuth.RefreshToken(ctx, &pb.RefreshTokenRequest{RefreshToken: refreshToken})
}

func (c *Client) RevokeToken(ctx context.Context, accessToken string, all bool) error {
	_, err := c.svcAuth.RevokeToken(ctx, &pb.RevokeTokenRequest{
		AccessToken: accessToken,
		All:         all,
	})
	return err
}
