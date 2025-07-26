package httpproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type Config struct {
	ConnectTimeout  time.Duration
	IdleTimeout     time.Duration
	RequestTimeout  time.Duration
	ResponseTimeout time.Duration

	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int

	// TLS settings
	InsecureSkipVerify  bool
	TLSHandshakeTimeout time.Duration

	// Transport settings
	DisableKeepAlives  bool
	DisableCompression bool

	// Buffer sizes
	ReadBufferSize  int
	WriteBufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		ConnectTimeout:      30 * time.Second,
		IdleTimeout:         90 * time.Second,
		InsecureSkipVerify:  true,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
	}
}

func createTransport(config *Config) *http.Transport {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},

		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		MaxConnsPerHost:     config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleTimeout,

		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseTimeout,

		DisableKeepAlives:  config.DisableKeepAlives,
		DisableCompression: config.DisableCompression,

		ReadBufferSize:  config.ReadBufferSize,
		WriteBufferSize: config.WriteBufferSize,
	}
	return transport
}
