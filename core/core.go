package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== Config Structures ========================
type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}
type Inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Protocol string `json:"protocol"`
}
type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}
type ProxySettings struct {
	Server   string `json:"server"`
	ServerIP string `json:"server_ip,omitempty"`
	Token    string `json:"token"`
}
type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
)

// ======================== Core Logic ========================

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}

	var listeners []net.Listener
	for _, inbound := range globalConfig.Inbounds {
		listener, err := net.Listen("tcp", inbound.Listen)
		if err != nil {
			log.Printf("[Error] Listen failed on %s: %v", inbound.Listen, err)
			return nil, err
		}
		log.Printf("[Inbound] Listening on %s (%s)", inbound.Listen, inbound.Tag)
		listeners = append(listeners, listener)

		go func(l net.Listener, tag string) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go handleGeneralConnection(conn, tag)
			}
		}(listener, inbound.Tag)
	}
	return &multiListener{listeners: listeners}, nil
}

type multiListener struct{ listeners []net.Listener }

func (ml *multiListener) Accept() (net.Conn, error) { return nil, nil }
func (ml *multiListener) Close() error {
	for _, l := range ml.listeners {
		l.Close()
	}
	return nil
}
func (ml *multiListener) Addr() net.Addr {
	if len(ml.listeners) > 0 {
		return ml.listeners[0].Addr()
	}
	return nil
}

func parseOutbounds() {
	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				proxySettingsMap[outbound.Tag] = settings
			}
		}
	}
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	var target string
	var err error
	var firstFrame []byte
	var mode int // 1=SOCKS5, 2=HTTP Connect, 3=HTTP Request

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	default:
		return
	}

	if err != nil {
		log.Printf("[Protocol Error] %v", err)
		return
	}

	outboundTag := route(target, inboundTag)
	log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	nmethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, nmethodsBuf); err != nil {
		return "", err
	}
	methods := make([]byte, int(nmethodsBuf[0]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	conn.Write([]byte{0x05, 0x00})

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[1] != 0x01 {
		return "", errors.New("unsupported command")
	}

	var host string
	switch header[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 3:
		b := make([]byte, 1)
		io.ReadFull(conn, b)
		d := make([]byte, b[0])
		io.ReadFull(conn, d)
		host = string(d)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	default:
		return "", errors.New("unsupported address type")
	}
	portBytes := make([]byte, 2)
	io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return target, nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", nil, 0, err
	}
	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	mode := 3
	if req.Method == "CONNECT" {
		mode = 2
	}
	var firstFrame []byte
	if mode == 3 {
		var buf bytes.Buffer
		req.WriteProxy(&buf)
		firstFrame = buf.Bytes()
	}
	return target, firstFrame, mode, nil
}

func route(target, inboundTag string) string {
	for _, rule := range globalConfig.Routing.Rules {
		if len(rule.InboundTag) > 0 {
			for _, t := range rule.InboundTag {
				if t == inboundTag {
					return rule.OutboundTag
				}
			}
		}
	}
	return "direct"
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	outbound, ok := findOutbound(outboundTag)
	if !ok {
		conn.Close()
		return
	}

	var err error
	switch outbound.Protocol {
	case "freedom":
		err = startDirectTunnel(conn, target, firstFrame, mode)
	case "ech-proxy":
		err = startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
	case "blackhole":
		conn.Close()
		return
	}

	if err != nil && err != io.EOF {
		log.Printf("[Error] Tunnel failed for %s: %v", target, err)
	}
}

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, mode int) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return err
	}
	defer remote.Close()
	if mode == 1 {
		local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}
	if len(firstFrame) > 0 {
		remote.Write(firstFrame)
	}
	go io.Copy(remote, local)
	io.Copy(local, remote)
	return nil
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		return err
	}
	defer wsConn.Close()

	stopPing := make(chan bool)
	defer close(stopPing)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				wsConn.WriteMessage(websocket.PingMessage, nil)
			case <-stopPing:
				return
			}
		}
	}()

	encodedFrame := ""
	if len(firstFrame) > 0 {
		encodedFrame = base64.StdEncoding.EncodeToString(firstFrame)
	}
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, encodedFrame)

	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil {
		return err
	}

	// 增加读取超时，避免卡死
	wsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	wsConn.SetReadDeadline(time.Time{}) // 重置超时

	if err != nil {
		return fmt.Errorf("read response failed: %v", err)
	}
	if string(msg) != "CONNECTED" {
		return fmt.Errorf("proxy handshake failed: %s", string(msg))
	}

	if mode == 1 {
		local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	done := make(chan bool, 2)
	go func() {
		buf := make([]byte, 32 * 1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				done <- true
				return
			}
			wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()
	go func() {
		for {
			mt, message, err := wsConn.ReadMessage()
			if err != nil {
				done <- true
				return
			}
			if mt == websocket.TextMessage && string(message) == "CLOSE" {
				done <- true
				return
			}
			if mt == websocket.BinaryMessage {
				local.Write(message)
			}
		}
	}()
	<-done
	return nil
}

func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("settings not found")
	}

	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: host},
		HandshakeTimeout: 10 * time.Second,
		Subprotocols:     []string{settings.Token},
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("connect failed (HTTP %d): %v", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("connect failed: %v", err)
	}
	return conn, nil
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
		err = nil
	}
	return
}

func findOutbound(tag string) (Outbound, bool) {
	for _, ob := range globalConfig.Outbounds {
		if ob.Tag == tag {
			return ob, true
		}
	}
	return Outbound{}, false
}

func getExeDir() string {
	exePath, _ := os.Executable()
	return filepath.Dir(exePath)
}
