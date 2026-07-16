package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

type contextKey string

const UserContextKey contextKey = "identity"

func GetUser(ctx context.Context) *pb.ValidateSessionResponse {
	if user, ok := ctx.Value(UserContextKey).(*pb.ValidateSessionResponse); ok {
		return user
	}
	return nil
}

type Client struct {
	svcAuth pb.AuthServiceClient
	svcUser pb.UserServiceClient
	grpccon *grpc.ClientConn
	natscon *nats.Conn
}

type Option func(*clientConfig)

type clientConfig struct {
	connectTimeout   time.Duration
	keepaliveTime    time.Duration
	keepaliveTimeout time.Duration
}

func WithConnectTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.connectTimeout = d }
}

func WithKeepalive(interval, timeout time.Duration) Option {
	return func(c *clientConfig) {
		c.keepaliveTime = interval
		c.keepaliveTimeout = timeout
	}
}

func NewClient(target, authority string, opts ...Option) (*Client, error) {
	cfg := clientConfig{
		connectTimeout:   3 * time.Second,
		keepaliveTime:    20 * time.Second,
		keepaliveTimeout: 20 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}

	dialOpts := []grpc.DialOption{
		grpc.WithAuthority(authority),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			loggingInterceptor(),
			errorInterceptor(),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			PermitWithoutStream: true,
			Time:                cfg.keepaliveTime,
			Timeout:             cfg.keepaliveTimeout,
		}),
	}

	log.Info().Msgf("connecting to Identity Service at %s", target)

	const maxRetries = 5
	var conn *grpc.ClientConn

	for attempt := range maxRetries {
		c, err := grpc.NewClient(target, dialOpts...)
		if err != nil {
			return nil, err
		}
		c.Connect()

		ctx, cancel := context.WithTimeout(context.Background(), cfg.connectTimeout)
		ready := false
		for {
			state := c.GetState()
			if state == connectivity.Ready {
				ready = true
				break
			}
			if !c.WaitForStateChange(ctx, state) {
				break
			}
		}
		cancel()

		if ready {
			conn = c
			log.Info().Msg("Identity Service connection established")
			break
		}

		c.Close()
		log.Warn().Int("attempt", attempt+1).Int("max", maxRetries).Msg("identity service not ready, retrying...")
		time.Sleep(time.Duration(500<<attempt) * time.Millisecond)
	}

	if conn == nil {
		return nil, fmt.Errorf("identity service unreachable after %d attempts", maxRetries)
	}

	return &Client{
		svcAuth: pb.NewAuthServiceClient(conn),
		svcUser: pb.NewUserServiceClient(conn),
		grpccon: conn,
	}, nil
}

func (c *Client) Close() error {
	if c.natscon != nil {
		if err := c.natscon.Drain(); err != nil {
			return err
		}
	}
	if c.grpccon != nil {
		return c.grpccon.Close()
	}
	return nil
}

func errorInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				return status.Error(codes.Unavailable, "infrastructure-routing-failure")
			}
			if st.Code() == codes.Internal || st.Code() == codes.Unknown || st.Code() == codes.Unimplemented {
				if len(st.Details()) > 0 {
					return status.Error(codes.Unavailable, "backend-handshake-failure")
				}
			}
		}
		return err
	}
}

func loggingInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		duration := time.Since(start)
		l := log.With().Str("method", method).Str("target", cc.Target()).Str("in", duration.String()).Logger()
		if err != nil {
			l.Error().Err(err).Msg("grpc client request failed")
		} else {
			l.Debug().Msg("grpc client")
		}
		return err
	}
}
