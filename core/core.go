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
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// JsonEnvelope 用于 WebSocket 消息封装
type JsonEnvelope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	TS   int64  `json:"ts"`
	Data string `json:"data"`
}

// ======================== Config Structures ========================
// 这些结构体必须与 C 客户端生成的 JSON 严格对应
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
// 这里的 Token 是 C 客户端加密后的 Base64 字符串
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
	globalConfig      Config
	proxySettingsMap  = make(map[string]ProxySettings)
	chinaIPRanges     []ipRange
	chinaIPV6Ranges   []ipRangeV6
	chinaIPRangesMu   sync.RWMutex
	chinaIPV6RangesMu sync.RWMutex
)
type ipRange struct{ start uint32; end uint32 }
type ipRangeV6 struct{ start [16]byte; end [16]byte }

// ======================== Core Logic ========================

func wrapAsJson(payload []byte) ([]byte, error) {
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
	envelope := JsonEnvelope{
		ID:   fmt.Sprintf("msg_%x", idBytes),
		Type: "sync_data",
		TS:   time.Now().UnixMilli(),
		Data: base64.StdEncoding.EncodeToString(payload),
	}
	return json.Marshal(envelope)
}

func unwrapFromJson(rawMsg []byte) ([]byte, error) {
	var envelope JsonEnvelope
	if err := json.Unmarshal(rawMsg, &envelope); err != nil {
		return nil, fmt.Errorf("not a valid json envelope: %w", err)
	}
	if envelope.Type == "pong" { return nil, nil }
	if envelope.Type != "sync_data" { return nil, errors.New("not a sync_data type message") }
	return base64.StdEncoding.DecodeString(envelope.Data)
}

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	// 暂时注释掉加载 IP 库，防止因为文件不存在导致启动失败，你可以把 ip 文件放在同级目录后再开启
	// loadChinaListsForRouter() 
	parseOutbounds()
	
	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen failed on %s: %v", inbound.Listen, err)
	}
	log.Printf("[Core] SOCKS5 Listening on %s", inbound.Listen)
	
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
	var mode int // 1: SOCKS5, 2: CONNECT, 3: HTTP Proxy

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
		log.Printf("[%s] Protocol handshake failed: %v", inboundTag, err)
		return
	}

	// 简单路由：直接查找名为 "proxy" 的 outbound
	// 因为 V2.0 客户端生成的 config.json 默认只有 "direct", "block", "proxy"
	outboundTag := "proxy"
	
	// 如果需要路由逻辑，可以恢复 route() 函数调用
	// outboundTag = route(target, inboundTag)

	log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr(), target, outboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	// 标准 SOCKS5 握手
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return "", err }
	conn.Write([]byte{0x05, 0x00}) // 无需认证
	
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil { return "", err }
	
	var host string
	switch header[3] {
	case 1: // IPv4
		b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: // Domain
		b := make([]byte, 1); io.ReadFull(conn, b); 
		d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: // IPv6
		b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	default: 
		return "", errors.New("unsupported addr type")
	}
	
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	// 简单的 HTTP 嗅探
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil { return "", nil, 0, err }
	
	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" { target += ":443" } else { target += ":80" }
	}

	if req.Method == "CONNECT" {
		return target, nil, 2, nil
	}
	
	// 普通 HTTP 代理，需要把请求重新写出去
	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	// 如果是直连
	if outboundTag == "direct" {
		startDirectTunnel(conn, target, firstFrame, mode)
		return
	}
	
	// 代理连接
	startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
}

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, mode int) {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil { return }
	defer remote.Close()
	
	if mode == 1 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	if len(firstFrame) > 0 { remote.Write(firstFrame) }
	
	go io.Copy(remote, local)
	io.Copy(local, remote)
}

// 【关键】此函数必须保留 JSON 消息协议，以配合你的 "Legacy Adapter" JS 服务端
func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil { return err }
	defer wsConn.Close()

	// 发送握手包 (X-LINK:target|base64_first_frame)
	connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	jsonHandshake, _ := wrapAsJson([]byte(connectMsg))
	
	// 客户端可以先发送一点噪音，JS 服务端 v2.1 能够忽略它 (可选)
	// noise := make([]byte, 100); rand.Read(noise); wsConn.WriteMessage(websocket.BinaryMessage, noise)

	if err := wsConn.WriteMessage(websocket.TextMessage, jsonHandshake); err != nil { return err }

	// 等待 "X-LINK-OK"
	_, msg, err := wsConn.ReadMessage()
	if err != nil { return err }
	
	okPayload, err := unwrapFromJson(msg)
	if err != nil || string(okPayload) != "X-LINK-OK" {
		return fmt.Errorf("handshake failed")
	}
    
	// 响应本地客户端连接成功
	if mode == 1 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	// 开始 JSON 数据流转发
	done := make(chan bool, 2)

	// 本地 -> 远程 (JSON 包装)
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				jsonData, _ := wrapAsJson(buf[:n])
				wsConn.WriteMessage(websocket.TextMessage, jsonData)
			}
			if err != nil { break }
		}
		done <- true
	}()

	// 远程 -> 本地 (JSON 解包)
	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil { break }
			payload, _ := unwrapFromJson(msg)
			if payload != nil {
				local.Write(payload)
			}
		}
		done <- true
	}()

	<-done
	return nil
}

func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	// 这里的 settings.Token 已经是 C 客户端生成的 Base64 字符串了
	// 我们直接把它放入 Sec-WebSocket-Protocol 头部
	
	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		Subprotocols:    []string{settings.Token}, // 关键：Token 放在这里
	}
	
	if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil { host = addr; port = "443"; err = nil }
	return
}
