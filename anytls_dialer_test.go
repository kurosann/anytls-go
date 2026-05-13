package anytls_go

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func httpGet(ctx context.Context, dialer *AnytlsDialer, host, path string) (string, error) {
	conn, err := dialer.DialContext(ctx, "tcp", host+":80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	resp := string(buf[:n])
	if idx := strings.Index(resp, "\r\n\r\n"); idx != -1 {
		return strings.TrimSpace(resp[idx+4:]), nil
	}
	return resp, nil
}

func TestAnytlsDialer_HongKong(t *testing.T) {
	config := &AnytlsConfig{
		ServerAddr:  "",
		Password:    "",
		SNI:         "",
		InsecureSkipVerify: true,
		ALPN:        []string{"http/1.1", "h2"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ad := NewAnytlsDialer(ctx, config)
	defer ad.Close()

	// Connectivity check
	body, err := httpGet(ctx, ad, "cp.cloudflare.com", "/generate_204")
	if err != nil {
		t.Fatalf("connectivity check failed: %v", err)
	}
	t.Logf("cp.cloudflare.com/generate_204: %s", body)

	// Get public IP
	ip, err := httpGet(ctx, ad, "httpbin.org", "/ip")
	if err != nil {
		t.Fatalf("get IP failed: %v", err)
	}
	t.Logf("%s", ip)

	// Get region info
	region, err := httpGet(ctx, ad, "ip-api.com", "/line/?fields=country,regionName,city,isp,query")
	if err != nil {
		t.Fatalf("get region failed: %v", err)
	}
	t.Logf("%s", region)
}
