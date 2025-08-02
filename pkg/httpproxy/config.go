package httpproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

var DefaultProxyTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	TLSHandshakeTimeout:   10 * time.Second,
	DisableCompression:    true,
	IdleConnTimeout:       90 * time.Second,
	ExpectContinueTimeout: 10 * time.Second,
}
