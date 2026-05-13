package anytls_go

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/kurosann/anytls-go/proxy/padding"
	"github.com/kurosann/anytls-go/proxy/session"

	"github.com/sagernet/sing/common/buf"
)

type AnytlsConfig struct {
	ServerAddr         string
	Password           string
	SNI                string
	InsecureSkipVerify bool
	ALPN               []string
	MinIdleSession     int
	DialTimeout        time.Duration
	IdleTimeout        time.Duration
}

func (c *AnytlsConfig) initDefaults() {
	if c.MinIdleSession <= 0 {
		c.MinIdleSession = 1
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 30 * time.Second
	}
}

type AnytlsDialer struct {
	serverAddr string
	password   [32]byte
	client     *session.Client
}

func NewAnytlsDialer(ctx context.Context, config *AnytlsConfig) *AnytlsDialer {
	config.initDefaults()

	d := &AnytlsDialer{
		serverAddr: config.ServerAddr,
		password:   sha256.Sum256([]byte(config.Password)),
	}

	td := &tlsDialer{
		dialer: &net.Dialer{Timeout: config.DialTimeout},
		tlsConfig: &tls.Config{
			ServerName:         config.SNI,
			InsecureSkipVerify: config.InsecureSkipVerify,
			NextProtos:         config.ALPN,
		},
	}

	d.client = session.NewClient(ctx, d.createOutboundConnection(td),
		&padding.DefaultPaddingFactory, config.IdleTimeout, config.IdleTimeout, config.MinIdleSession)
	return d
}

func (d *AnytlsDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *AnytlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.client.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	destination := M.ParseSocksaddr(address)
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &closeConn{Conn: conn, client: d.client}, nil
}

func (d *AnytlsDialer) Close() error {
	return d.client.Close()
}

func (d *AnytlsDialer) createOutboundConnection(tlsDialer *tlsDialer) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := tlsDialer.DialContext(ctx, "tcp", d.serverAddr)
		if err != nil {
			return nil, err
		}

		b := buf.NewPacket()
		defer b.Release()
		b.Write(d.password[:])
		var paddingLen int
		if pad := padding.DefaultPaddingFactory.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
			paddingLen = pad[0]
		}
		binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
		if paddingLen > 0 {
			b.WriteZeroN(paddingLen)
		}
		_, err = b.WriteTo(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

type tlsDialer struct {
	dialer    *net.Dialer
	tlsConfig *tls.Config
}

func (d *tlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, d.tlsConfig.Clone()), nil
}

type closeConn struct {
	net.Conn
	client    *session.Client
	closeOnce sync.Once
}

func (c *closeConn) Close() error {
	c.closeOnce.Do(func() { c.client.Close() })
	return c.Conn.Close()
}
