package identity

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

type EventHandler func(data *nats.Msg) error

func (c *Client) ConnectNATS(natsURL string) error {
	nc, err := nats.Connect(natsURL,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return err
	}
	c.natscon = nc
	return nil
}

func (c *Client) Subscribe(subject string, handler EventHandler) error {
	if c.natscon == nil {
		return fmt.Errorf("nats not connected: call ConnectNATS first")
	}
	_, err := c.natscon.Subscribe(subject, func(msg *nats.Msg) {
		if err := handler(msg); err != nil {
			log.Error().Err(err).Str("subject", msg.Subject).Msg("event handler error")
		}
	})
	return err
}

func (c *Client) QueueSubscribe(subject, queue string, handler EventHandler) error {
	if c.natscon == nil {
		return fmt.Errorf("nats not connected: call ConnectNATS first")
	}
	_, err := c.natscon.QueueSubscribe(subject, queue, func(msg *nats.Msg) {
		if err := handler(msg); err != nil {
			log.Error().Err(err).Str("subject", msg.Subject).Msg("event handler error")
		}
	})
	return err
}
