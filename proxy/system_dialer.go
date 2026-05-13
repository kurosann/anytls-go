package proxy

import (
	"context"
	"net"
	"time"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var SystemDialer = &net.Dialer{
	Timeout: time.Second * 5,
}
