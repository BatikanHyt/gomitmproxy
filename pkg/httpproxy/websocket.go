package httpproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketMessage represents a WebSocket message for MITM
type WebSocketMessage struct {
	Type       int // websocket.TextMessage, websocket.BinaryMessage, etc.
	Data       []byte
	FromClient bool // true if from client, false if from server
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
	HandshakeTimeout: 45 * time.Second,
}

func isWebsocketUpgrade(req *http.Request) bool {
	upgrade := false
	for _, header := range req.Header.Values("Upgrade") {
		if strings.EqualFold(header, "websocket") {
			upgrade = true
			break
		}
	}
	if !upgrade {
		return false
	}
	for _, header := range req.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(header), "upgrade") {
			return true
		}
	}
	return false
}

func isSecureWebsocket(req *http.Request) bool {
	return req.URL.Scheme == "wss" || req.TLS != nil
}

func (proxy *HttpProxy) handleWebsocket(w http.ResponseWriter, req *http.Request) {
	if proxy.OnWsConnect != nil {
		action, response := proxy.OnWsConnect(req)
		switch action {
		case Reject:
			w.WriteHeader(http.StatusForbidden)
			if response != nil {
				w.Write(response)
			}
		case Accept:
			proxy.tunnelWebSocket(w, req)
			return
		case Mitm:
			proxy.mitmWebsocket(w, req)
			return
		}
	}
	proxy.tunnelWebSocket(w, req)
}

func (proxy *HttpProxy) tunnelWebSocket(w http.ResponseWriter, req *http.Request) {
	targetConn, clientConn, err := setupWSConnection(w, req)
	if err != nil {
		proxy.logger.Error("failed to setup websocket connection", "error", err)
		return
	}
	defer targetConn.Close()
	defer clientConn.Close()

	// Copy data bidirectionally
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errCh <- err
	}()

	// Wait for either direction to close
	<-errCh
	proxy.logger.Debug("WebSocket tunnel closed", "secure", isSecureWebsocket(req))
}

func (proxy *HttpProxy) mitmWebsocket(w http.ResponseWriter, req *http.Request) {
	clientConn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		proxy.logger.Error("failed to upgrade client connection", "error", err)
		return
	}
	defer clientConn.Close()

	targetURL := "ws://" + req.Host + req.URL.Path
	if isSecureWebsocket(req) {
		targetURL = "wss://" + req.Host + req.URL.Path
	}
	// Forward headers from original request
	headers := http.Header{}
	for k, v := range req.Header {
		if k != "Upgrade" && k != "Connection" && k != "Sec-Websocket-Key" &&
			k != "Sec-Websocket-Version" && k != "Sec-Websocket-Extensions" {
			headers[k] = v
		}
	}

	targetConn, _, err := websocket.DefaultDialer.Dial(targetURL, headers)
	if err != nil {
		proxy.logger.Error("failed to connect to target WebSocket", "error", err)
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseServiceRestart, "Proxy connection failed"))
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Handle client -> target messages
	go func() {
		defer wg.Done()
		proxy.handleWsConnection(clientConn, targetConn, true)
	}()

	// Handle target -> client messages
	go func() {
		defer wg.Done()
		proxy.handleWsConnection(targetConn, clientConn, false)
	}()

	wg.Wait()
	proxy.logger.Debug("WebSocket MITM closed", "secure", isSecureWebsocket(req))
}

func (proxy *HttpProxy) handleWsConnection(src, dest *websocket.Conn, fromClient bool) {
	for {
		messageType, data, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				proxy.logger.Error("websocket read error", "error", err, "fromClient", fromClient)
			}
			break
		}
		msg := &WebSocketMessage{
			Type:       messageType,
			Data:       data,
			FromClient: fromClient,
		}
		if proxy.OnWsMessage != nil {
			if modifiedMessage := proxy.OnWsMessage(msg); modifiedMessage != nil {
				msg = modifiedMessage
			}
		}
		if err := dest.WriteMessage(msg.Type, msg.Data); err != nil {
			proxy.logger.Error("failed to write to client", "error", err)
			break
		}
		proxy.logger.Debug("Forwarded target message", "type", messageType, "size", len(data))
	}
}

// setupWSConnection establishes raw TCP connection for tunneling
func setupWSConnection(w http.ResponseWriter, req *http.Request) (net.Conn, net.Conn, error) {
	var targetConn net.Conn
	var err error

	// Connect to target server
	if isSecureWebsocket(req) {
		targetConn, err = tls.Dial("tcp", req.Host, &tls.Config{
			ServerName: strings.Split(req.Host, ":")[0],
		})
	} else {
		targetConn, err = net.Dial("tcp", req.Host)
	}

	if err != nil {
		http.Error(w, "Failed to connect to target", http.StatusServiceUnavailable)
		return nil, nil, fmt.Errorf("failed to dial websocket target. Host %s, secure %t, error %w", req.Host, isSecureWebsocket(req), err)
	}

	// Forward the original request to the target
	err = req.Write(targetConn)
	if err != nil {
		targetConn.Close()
		http.Error(w, "Failed to forward request", http.StatusServiceUnavailable)
		return nil, nil, fmt.Errorf("failed to write WebSocket request to target: %w", err)
	}

	// Read the response from target
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		targetConn.Close()
		http.Error(w, "Failed to read response", http.StatusServiceUnavailable)
		return nil, nil, fmt.Errorf("failed to read WebSocket response from target: %w", err)
	}

	// Copy response headers to client
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// If upgrade successful, hijack the connection
	if resp.StatusCode == http.StatusSwitchingProtocols {
		hj, ok := w.(http.Hijacker)
		if !ok {
			targetConn.Close()
			return nil, nil, fmt.Errorf("hijacking not supported")
		}

		clientConn, _, err := hj.Hijack()
		if err != nil {
			targetConn.Close()
			return nil, nil, fmt.Errorf("failed to hijack client connection: %w", err)
		}

		return targetConn, clientConn, nil
	}

	targetConn.Close()
	return nil, nil, fmt.Errorf("failed to switch protocol, status: %d", resp.StatusCode)
}
