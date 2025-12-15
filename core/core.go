// core/core.go (Ultimate Performance Edition - Binary Protocol)
package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
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
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// 配置结构体保持不变，兼容 C 客户端生成的 config.json
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
	ServerIP string `json:"server_ip"`
	Token    string `json:"token"`
}
type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	GeoIP       string   `json:"geoip,omitempty"`
	Port        []int    `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
)

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	log.Printf("[Core] Listening on %s (Binary Mode)", inbound.Listen)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { break }
			go handleGeneralConnection(conn, inbound.Tag)
		}
	}()
	return listener, nil
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
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }

	var target string
	var err error
	var firstFrame []byte
	var mode int 

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default: 
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}

	if err != nil {
		log.Printf("[ERROR] Handshake: %v", err)
		return
	}

	log.Printf("[%s] Request -> %s", inboundTag, target)
	startProxyTunnelBinary(conn, target, "proxy", firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf)
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4); io.ReadFull(conn, header)
	var host string
	switch header[3] {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil { return "", nil, 0, err }
	target := req.Host
	if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }
	if req.Method == "CONNECT" { return target, nil, 2, nil }
	var buf bytes.Buffer; req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}

// 【终极性能核心】使用二进制流协议，零拷贝转发
func startProxyTunnelBinary(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		log.Printf("[ERROR] Connect proxy failed: %v", err)
		return
	}
	defer wsConn.Close()

	// 1. 构建二进制握手包 (0x01 0x01 | ADDR)
	// 格式: [HEAD 2][TYPE 1][HOST VAR][PORT 2][DATA VAR]
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x01}) // 协议头

	host, portStr, _ := net.SplitHostPort(target)
	portInt, _ := net.LookupPort("tcp", portStr)
	
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf.WriteByte(0x01)
		buf.Write(ip4)
	} else {
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}
	
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	buf.Write(portBytes)
	
	if len(firstFrame) > 0 {
		buf.Write(firstFrame)
	}

	log.Printf("[Debug] Sending Binary Handshake...")
	if err := wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil {
		log.Printf("[ERROR] Write handshake failed: %v", err)
		return
	}

	// 2. 等待二进制响应 (0x01 0x00)
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		log.Printf("[ERROR] Read response failed: %v", err)
		return
	}
	if len(msg) < 2 || msg[0] != 0x01 || msg[1] != 0x00 {
		log.Printf("[ERROR] Handshake rejected. Response: %x", msg)
		return
	}

	log.Printf("[Success] Tunnel established (Binary Mode)")

	// 3. 响应本地
	if mode == 1 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }

	// 4. 极速双向流转发 (Pipe)
	// 使用 io.Copy 实现内核级数据搬运，无需 JS/JSON 介入
	
	// WebSocket -> Local
	go func() {
		for {
			mt, r, err := wsConn.NextReader()
			if err != nil { break }
			if mt == websocket.BinaryMessage {
				if _, err := io.Copy(local, r); err != nil { break }
			}
		}
		local.Close()
	}()

	// Local -> WebSocket
	// 使用 NextWriter 减少内存分配
	bufCopy := make([]byte, 32*1024)
	for {
		n, err := local.Read(bufCopy)
		if n > 0 {
			w, err := wsConn.NextWriter(websocket.BinaryMessage)
			if err != nil { break }
			w.Write(bufCopy[:n])
			w.Close()
		}
		if err != nil { break }
	}
}

func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	requestHeader := http.Header{}
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	requestHeader.Add("Host", host)
	requestHeader.Add("Origin", fmt.Sprintf("https://%s", host))

	log.Printf("[Debug] Dialing: %s (IP: %s)", wsURL, settings.ServerIP)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		Subprotocols:    []string{settings.Token},
		HandshakeTimeout: 10 * time.Second,
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("HTTP %s (Code: %d)", resp.Status, resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }
	host, port, err = net.SplitHostPort(addr)
	if err != nil { host = addr; port = "443"; err = nil }
	return
}
