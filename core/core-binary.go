// core/core-binary.go (v10.2 - Nano Feature Complete)
// 适配 v10.2 服务端：支持 URL Token 鉴权，支持发送 SOCKS5 和 Fallback 信息

//go:build binary
// +build binary

package core

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// --- 结构定义 (与 GUI 生成的 config.json 结构匹配) ---
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"`; ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }

var ( 
	globalConfig Config
	proxySettingsMap = make(map[string]ProxySettings)
)

// ======================== 核心入口 ========================

func StartInstance(configContent []byte) (net.Listener, error) {
	// 重置 Map 防止残留
	proxySettingsMap = make(map[string]ProxySettings)
	
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { 
		return nil, err 
	}
	
	parseOutbounds()
	
	if len(globalConfig.Inbounds) == 0 { 
		return nil, errors.New("no inbounds") 
	}
	
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { 
		return nil, err 
	}
	
	log.Printf("[Core] Xlink Nano Engine (v10.2 Complete) Listening on %s", inbound.Listen)
	
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

// ======================== 连接处理 ========================

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	
	// 预读取 1 字节，判断是 SOCKS5 握手还是 HTTP 请求
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	
	var target string
	var err error
	var firstFrame []byte
	var mode int // 1=SOCKS5, 2=HTTP Connect, 3=HTTP Direct

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	
	if err != nil { 
		// log.Printf("Handshake failed: %v", err)
		return 
	}

	// 建立到 Cloudflare Workers 的 WebSocket 隧道
	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil { 
		// log.Printf("Tunnel failed: %v", err)
		return 
	}
	defer wsConn.Close()

	// 握手成功，响应本地客户端
	if mode == 1 { 
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
	}
	if mode == 2 { 
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) 
	}
	
	// 进入纯管道传输模式
	pipeDirect(conn, wsConn)
}

func connectNanoTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	// 1. 提取 Token 和 Fallback
	// 兼容处理：用户可能在 Token 字段输入 "mytoken|fallbackIP"
	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 { 
		fallback = parts[1] 
	}

	// 2. 提取 SOCKS5
	// GUI 传入的 ForwarderSettings.Socks5Address 意为“让服务端去连接的 S5”
	socks5 := ""
	if settings.ForwarderSettings != nil { 
		socks5 = settings.ForwarderSettings.Socks5Address 
	}

	// 3. 建立 WebSocket 连接 (使用 URL Token 鉴权)
	wsConn, err := dialCleanWebSocket(settings, secretKey)
	if err != nil { return nil, err }

	// 4. 发送 v10.2 协议头 (包含 Target, S5, Fallback, Payload)
	err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
	if err != nil {
		wsConn.Close()
		return nil, err
	}
	return wsConn, nil
}

func dialCleanWebSocket(settings ProxySettings, token string) (*websocket.Conn, error) {
	host, port, path, _ := parseServerAddr(settings.Server)
	
	// 关键：将 Token 拼接到 URL 参数中
	wsURL := fmt.Sprintf("wss://%s:%s%s?token=%s", host, port, path, url.QueryEscape(token))
	
	requestHeader := http.Header{}
	requestHeader.Add("Host", host)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	
	dialer := websocket.Dialer{ 
		TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: host }, 
		HandshakeTimeout: 5 * time.Second,
	}
	
	// 处理 ServerIP 指定 (Hosts 强制解析)
	if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) { 
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second) 
		}
	}

	// 注意：此处不处理本地到 CF 的 SOCKS5 前置（Client-Side Proxy），
	// 因为 GUI 中的 Socks5Address 定义为服务端用的（Server-Side Proxy）。
	// 如需本地代理，需额外增加配置字段。

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil { 
		if resp != nil { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }
		return nil, err 
	}
	return conn, nil
}

// [v10.2] Nano 协议发送：支持 S5 和 Fallback
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	hostBytes := []byte(host)
	s5Bytes := []byte(s5)
	fbBytes := []byte(fb)

	// 长度检查 (使用 1 Byte 存储长度，最大 255)
	if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 {
		return errors.New("address length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)
	
	// 1. Target [Len][Host][Port]
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)
	portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, port); buf.Write(portBytes)
	
	// 2. SOCKS5 [Len][String]
	buf.WriteByte(byte(len(s5Bytes)))
	if len(s5Bytes) > 0 { buf.Write(s5Bytes) }

	// 3. Fallback [Len][String]
	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 { buf.Write(fbBytes) }

	// 4. Payload (Early Data)
	if len(payload) > 0 { buf.Write(payload) }

	// 一次性发送
	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// --- 辅助函数 ---
func pipeDirect(local net.Conn, ws *websocket.Conn) { 
	defer ws.Close()
	go func() { 
		for { 
			mt, r, err := ws.NextReader()
			if err != nil { break }
			if mt == websocket.BinaryMessage { io.Copy(local, r) }
		} 
		local.Close() 
	}() 
	buf := make([]byte, 32*1024)
	for { 
		n, err := local.Read(buf)
		if n > 0 { 
			err := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
			if err != nil { break }
		} 
		if err != nil { break }
	} 
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
	if !strings.Contains(target, ":") { 
		if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } 
	}
	if req.Method == "CONNECT" { return target, nil, 2, nil }
	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil 
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
