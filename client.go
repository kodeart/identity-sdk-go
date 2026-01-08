package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	pb "github.com/kodeart/identity-sdk-go/proto/v1"
)

type Client struct {
	grpcsvc pb.IdentityServiceClient
	conn    *grpc.ClientConn
}

func NewClient(addr string) (*Client, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultServiceConfig(`{
        "methodConfig": [{
            "name": [{"service": ""}], 
            "retryPolicy": {
                "maxAttempts": 5,
                "initialBackoff": "0.1s",
                "maxBackoff": "1s",
                "backoffMultiplier": 2.0,
                "retryableStatusCodes": ["UNAVAILABLE"]
            }
        }]}`),
	}
	log.Info().Msgf("connecting to Identity Service at %s", addr)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}

	// Trigger connection, force the background connector to start immediately
	conn.Connect()

	// Some sanity check
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if !conn.WaitForStateChange(ctx, connectivity.Ready) {
		log.Warn().Msgf("Identity Service not ready yet, proceeding in background...")
	} else {
		log.Info().Msgf("Identity Service connection established")
	}

	return &Client{
		grpcsvc: pb.NewIdentityServiceClient(conn),
		conn:    conn,
	}, nil
}

// AuthenticateWithProvider is what the frontend calls
// after getting a token from the external auth provider.
func (c *Client) AuthenticateWithProvider(ctx context.Context, tenantSlug, providerToken string) (*pb.AuthenticateResponse, error) {
	return c.grpcsvc.Authenticate(ctx, &pb.AuthenticateRequest{
		TenantSlug: tenantSlug,
		Credentials: &pb.AuthenticateRequest_ProviderToken{
			ProviderToken: providerToken,
		},
	})
}

func (c *Client) AuthenticateWithCredentials(ctx context.Context, tenantSlug, email, password string) (*pb.AuthenticateResponse, error) {
	return c.grpcsvc.Authenticate(ctx, &pb.AuthenticateRequest{
		TenantSlug: tenantSlug,
		Credentials: &pb.AuthenticateRequest_Credential{
			Credential: &pb.UserCredentials{
				Email:    email,
				Password: password,
			},
		},
	})
}

// ValidateSession is used by the middleware
// to check if the JWT from the request is valid.
func (c *Client) ValidateSession(ctx context.Context, token string) (*pb.User, error) {
	resp, err := c.grpcsvc.ValidateSession(ctx, &pb.ValidateSessionRequest{Token: token})
	if err != nil {
		return nil, err
	}
	if !resp.Valid {
		return nil, fmt.Errorf("invalid session")
	}
	return resp.User, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}
