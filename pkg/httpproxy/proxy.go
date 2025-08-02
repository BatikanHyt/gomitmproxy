package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/batikanhyt/gomitmproxy/pkg/cert"
)

// ConnectAction defines the action to take for CONNECT requests
type ConnectAction int

const (
	Reject ConnectAction = iota // Reject the CONNECT request
	Accept                      // Accept and tunnel the connection
	Mitm                        // Perform man-in-the-middle interception
)

// Interceptor function types
type (
	RequestInterceptor  func(*http.Request)
	ResponseInterceptor func(*http.Response) error
	ConnectInterceptor  func(*http.Request) (ConnectAction, []byte)
	WsInterceptor       func(*WebSocketMessage) *WebSocketMessage
)

// Predefined connect interceptors
var (
	RejectConnect = func(req *http.Request) (ConnectAction, []byte) { return Reject, nil }
	AcceptConnect = func(req *http.Request) (ConnectAction, []byte) { return Accept, nil }
	MitmConnect   = func(req *http.Request) (ConnectAction, []byte) { return Mitm, nil }
)

// WebSocketMessage represents a WebSocket message for MITM
type WebSocketMessage struct {
	Type       int // websocket.TextMessage, websocket.BinaryMessage, etc.
	Data       []byte
	FromClient bool // true if from client, false if from server
}

type HttpProxy struct {
	OnRequest   []RequestInterceptor
	OnResponse  []ResponseInterceptor
	OnConnect   ConnectInterceptor
	OnWsConnect ConnectInterceptor
	OnWsMessage WsInterceptor

	handler   http.Handler
	cm        *cert.CertManager
	logger    *slog.Logger
	Transport *http.Transport
	isReverse bool
}

func NewHttpProxy(certManager *cert.CertManager) (*HttpProxy, error) {
	if certManager == nil {
		cm, err := cert.NewCertManager(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate manager: %w", err)
		}
		certManager = cm
	}
	p := &HttpProxy{cm: certManager, Transport: DefaultProxyTransport}
	p.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p.ClearRequestMiddlewares()
	p.ClearResponseMiddlewares()
	p.handler = &httputil.ReverseProxy{
		Director:       p.modifyRequest,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		Transport:      p.Transport,
	}

	return p, nil
}

func NewHttpReverseProxy(target string) (*HttpProxy, error) {
	url, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	p := &HttpProxy{Transport: DefaultProxyTransport, isReverse: true}
	p.ClearRequestMiddlewares()
	p.ClearResponseMiddlewares()

	handler := httputil.NewSingleHostReverseProxy(url)
	handler.ModifyResponse = p.modifyResponse
	handler.ErrorHandler = p.errorHandler
	handler.Transport = p.Transport
	originalDirectory := handler.Director
	directory := func(req *http.Request) {
		originalDirectory(req)
		p.modifyRequest(req)
	}
	handler.Director = directory
	p.handler = handler
	return p, nil
}

func (proxy *HttpProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect && !proxy.isReverse {
		proxy.handleConnect(w, req)
		return
	}
	if isWebsocketUpgrade(req) {
		proxy.handleWebsocket(w, req)
		return
	}
	proxy.handler.ServeHTTP(w, req)
}

func (proxy *HttpProxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	if proxy.OnConnect != nil {
		action, response := proxy.OnConnect(req)
		switch action {
		case Reject:
			w.WriteHeader(http.StatusForbidden)
			if response != nil {
				w.Write(response)
			}
			return
		case Accept:
			proxy.tunnelConnection(w, req)
			return
		case Mitm:
			proxy.mitmConnection(w, req)
			return
		}
	}

	// Default tunnel connection
	proxy.tunnelConnection(w, req)
}

func (proxy *HttpProxy) tunnelConnection(w http.ResponseWriter, req *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusServiceUnavailable)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		proxy.logger.Error("failed to write 200 response", "error", err)
		return
	}
	serverConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		proxy.logger.Error("failed to dial host", "host", req.Host, "error", err)
		return
	}
	defer serverConn.Close()

	// Copy data bidirectionally
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errCh <- err
	}()

	// Wait for either direction to close
	<-errCh
}

func (proxy *HttpProxy) mitmConnection(w http.ResponseWriter, req *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusServiceUnavailable)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		proxy.logger.Error("failed to write 200 response", "error", err)
		return
	}

	bufferedClient := bufio.NewReader(clientConn)
	connWrapper := &BufferedConn{Conn: clientConn, Reader: bufferedClient}
	peek, err := connWrapper.Peek(3)
	if err != nil {
		proxy.logger.Error("failed to check connection type", "error", err)
		return
	}

	host := req.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	if !isTls(peek) {
		fmt.Println("NORMAL CONNECTION")
		notify := ConnNotify{connWrapper, make(chan struct{})}
		l := &OnceAcceptListener{notify.Conn}
		err := http.Serve(l, proxy)
		if err != nil && !errors.Is(err, ErrAlreadyAccepted) {
			proxy.logger.Error("failed to serve plain HTTP request", "error", err)
		}

		<-notify.closed
		return
	}

	proxy.logger.Debug("Running normal tls connection")
	config := &tls.Config{GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := host
		if chi.ServerName != "" {
			name = chi.ServerName
		}
		return proxy.cm.CreateGetCertHost(name)
	}}

	tlsClientConn := tls.Server(connWrapper, config)
	if err := tlsClientConn.Handshake(); err != nil {
		proxy.logger.Error("client TLS handshake failed.", "error", err)
		return
	}

	notify := ConnNotify{tlsClientConn, make(chan struct{})}
	l := &OnceAcceptListener{notify.Conn}
	err = http.Serve(l, proxy)
	if err != nil && !errors.Is(err, ErrAlreadyAccepted) {
		proxy.logger.Error("failed to server HTTP request.", "error", err)
	}

	<-notify.closed
}

func (proxy *HttpProxy) modifyRequest(req *http.Request) {
	proxy.logger.Debug("Request received", "req", req)
	// Fix URL for HTTPS requests after CONNECT
	if req.URL.Scheme == "" {
		req.URL.Host = req.Host
		req.URL.Scheme = "https"
	}

	// Remove X-Forwarded-For header to avoid loops
	delete(req.Header, "X-Forwarded-For")

	for _, fn := range proxy.OnRequest {
		fn(req)
	}
}

func (proxy *HttpProxy) modifyResponse(r *http.Response) error {
	proxy.logger.Debug("Response received", "Resp", r)

	for _, fn := range proxy.OnResponse {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func (proxy *HttpProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case !errors.Is(err, context.Canceled):
		proxy.logger.Error("proxy request cancelled", "method", r.Method, "url", r.URL.String(), "error", err)
	case errors.Is(err, context.Canceled):
		proxy.logger.Error("proxy request failed.", "method", r.Method, "url", r.URL.String(), "error", err)
	}

	w.WriteHeader(http.StatusBadGateway)
}

func (proxy *HttpProxy) UseRequest(fn RequestInterceptor) {
	proxy.OnRequest = append(proxy.OnRequest, fn)
}

func (proxy *HttpProxy) ClearRequestMiddlewares() {
	proxy.OnRequest = make([]RequestInterceptor, 0)
}

func (proxy *HttpProxy) UseResponse(fn ResponseInterceptor) {
	proxy.OnResponse = append(proxy.OnResponse, fn)
}

func (proxy *HttpProxy) ClearResponseMiddlewares() {
	proxy.OnResponse = make([]ResponseInterceptor, 0)
}

// https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py starts_like_tls_record
func isTls(buf []byte) bool {
	return len(buf) > 2 && buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03
}
