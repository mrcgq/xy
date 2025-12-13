// ech-proxy-core.go - v10.0 (Path Auth Edition - The VLESS Way)
// 协议内核：完全模仿 VLESS 的行为模式。
// 1. 使用 URL Path (/token) 传递认证。
// 2. 使用标准 Go TLS 指纹，避免 uTLS 的复杂性。
// 3. 保留 SOCKS5 首包修复。
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== Config & Global State (No changes) ========================
type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }
var ( proxySettingsMap = make(map[string]ProxySettings) )

func main() {
	configPath := flag.String("c", "config.json", "Path to config")
	flag.Parse()
	log.Println("[Core] X-Link Kernel v10.0 (Path Auth) Starting...")
	file, err := os.ReadFile(*configPath)
	if err != nil { log.Fatalf("Failed to read config: %v", err) }
	if err := json.Unmarshal(file, &file, &globalConfig); err != nil { log.Fatalf("Config parse error: %v", err) }
	for _, outbound := range globalConfig.Outbounds { if outbound.Protocol == "ech-proxy" { var settings ProxySettings; if err := json.Unmarshal(outbound.Settings, &settings); err == nil { proxySettingsMap[outbound.Tag] = settings } } }
	var wg sync.WaitGroup
	for _, inbound := range globalConfig.Inbounds {
		wg.Add(1)
		go func(ib Inbound) { defer wg.Done(); runInbound(ib) }(inbound)
	}
	log.Println("[Core] Engine started.")
	wg.Wait()
}

func runInbound(ib Inbound) {
    listener, err := net.Listen("tcp", ib.Listen)
    if err != nil { log.Printf("[Error] Listen failed on %s: %v", ib.Listen, err); return }
    log.Printf("[Inbound] Listening on %s (%s)", ib.Listen, ib.Tag)
    for { conn, err := listener.Accept(); if err != nil { continue }; go handleGeneralConnection(conn, ib.Tag) }
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
    defer conn.Close()
    buf := make([]byte, 1)
    if _, err := io.ReadFull(conn, buf); err != nil { return }
    var target string; var err error; var firstFrame []byte; var mode int
    switch buf[0] {
    case 0x05: target, err = handleSOCKS5(conn); mode = 1
    default: target, firstFrame, mode, err = handleHTTP(conn, buf)
    }
    if err != nil { return }
    outboundTag := "proxy" // Simplified routing
    log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)
    dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn) (string, error) {
    handshakeBuf := make([]byte, 2); if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return "", err }
    conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); if _, err := io.ReadFull(conn, header); err != nil { return "", err }
    if header[1] != 0x01 { conn.Write([]byte{0x05, 0x07, 0x00, 0x01}); return "", errors.New("unsupported command") }
    var host string
    switch header[3] {
    case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
    case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
    case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
    default: return "", errors.New("bad addr type")
    }
    portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes)
    return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte) (string, []byte, int, error) {
    reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
    req, err := http.ReadRequest(reader)
    if err != nil { return "", nil, 0, err }
    if req.Method == "CONNECT" { return req.Host, nil, 2, nil }
    var buf bytes.Buffer; req.WriteProxy(&buf); return req.Host, buf.Bytes(), 3, nil
}

const ( modeSOCKS5 = 1; modeHTTPConnect = 2; modeHTTPProxy = 3 )

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
    err := startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
    if err != nil { log.Printf("Tunnel failed for %s: %v", target, err) }
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
    if mode == modeSOCKS5 && len(firstFrame) == 0 {
        local.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
        buffer := make([]byte, 32*1024)
        n, readErr := local.Read(buffer)
        local.SetReadDeadline(time.Time{})
        if n > 0 { firstFrame = buffer[:n] }
        if readErr != nil && !os.IsTimeout(readErr) && readErr != io.EOF { return readErr }
    }

	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
		if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
		return err
	}
	defer wsConn.Close()

	var handshakeBuf bytes.Buffer
	addrLen := uint16(len(target)); binary.Write(&handshakeBuf, binary.BigEndian, addrLen)
	handshakeBuf.WriteString(target)
	if len(firstFrame) > 0 { handshakeBuf.Write(firstFrame) }
	if err := wsConn.WriteMessage(websocket.BinaryMessage, handshakeBuf.Bytes()); err != nil { return err }

	if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }

	done := make(chan bool, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if err != nil { wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); done <- true; return }
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { done <- true; return }
		}
	}()
	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil { local.Close(); done <- true; return }
			if _, err := local.Write(msg); err != nil { done <- true; return }
		}
	}()
	<-done; return nil
}

// 【核心修改】将 Token 放入 URL 路径
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	host, port, _, err := parseServerAddr(settings.Server)
	if err != nil { return nil, fmt.Errorf("invalid server address: %w", err) }

	// 将 Token 作为 Path，并进行 URL 编码
	// 格式: wss://host:port/TOKEN
	u := url.URL{
		Scheme: "wss",
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + url.PathEscape(settings.Token),
	}
	wsURL := u.String()

	tlsCfg := &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: host }
	
	// 只添加最标准的 User-Agent，不做任何多余的事
	customHeader := http.Header{}
	customHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}
	
	conn, _, err := dialer.Dial(wsURL, customHeader)
	return conn, err
}

func parseServerAddr(addr string) (host, port, path string, err error) { 
    path = "/"
    if idx := strings.Index(addr, "/"); idx != -1 { 
        path = addr[idx:]
        addr = addr[:idx] 
    }
    host, port, err = net.SplitHostPort(addr)
    return 
}
