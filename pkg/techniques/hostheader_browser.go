package techniques

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type hostHeaderBrowserTransport struct {
	h2 *http2.Transport
	h1 *http.Transport
}

func (t *hostHeaderBrowserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		if resp, err := t.h2.RoundTrip(req); err == nil {
			return resp, nil
		}
	}
	return t.h1.RoundTrip(req)
}

func newHostHeaderBrowserClient(timeout time.Duration, serverNameOverride string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	tcpDial := dialer.DialContext
	h1 := &http.Transport{
		DialContext:         tcpDial,
		DialTLSContext:      hostHeaderUTLSDialTLS(tcpDial, serverNameOverride, true),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}
	h2Dial := hostHeaderUTLSDialTLS(tcpDial, serverNameOverride, false)
	h2 := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return h2Dial(ctx, network, addr)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &hostHeaderBrowserTransport{h2: h2, h1: h1},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func hostHeaderUTLSDialTLS(tcpDial func(context.Context, string, string) (net.Conn, error), serverNameOverride string, forceH1 bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := tcpDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		serverName := serverNameOverride
		if serverName == "" {
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			serverName = host
		}
		cfg := &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
		if forceH1 {
			cfg.NextProtos = []string{"http/1.1"}
		}
		tlsConn := utls.UClient(conn, cfg, utls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}
