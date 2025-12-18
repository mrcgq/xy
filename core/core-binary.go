// core/core-binary.go (v6.4 Final Fix)
// 修复编译错误：变量重复声明
// 功能：强制硬编码密钥，对接 Ghost 服务端

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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

// --- 基础结构 ---
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"`; ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }
var ( globalConfig Config; proxySettingsMap = make(map[string]ProxySettings) )

// ======================== 入口函数 ========================
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	log.Printf("[Core] Xlink Ghost Engine (Binary) Listening on %s", inbound.Listen)
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

// ======================== 核心连接逻辑 ========================

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }

	var target string
	var err error
	var firstFrame []byte
	var mode int

	switch buf[0] {
	case 0x05: // SOCKS5
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default: // HTTP or other
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}

	if err != nil { return }
	
	// 连接 Ghost WebSocket
	wsConn, err := connectGhostTunnel(target, "proxy", firstFrame)
	if err != nil {
		return
	}
	
	// 响应本地客户端连接成功
	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	// 开始双向转发
	pipeDirect(conn, wsConn)
}

// 建立 Ghost 协议连接
// 修改后的 connectGhostTunnel (core-binary.go)
// 变更点：移除硬编码，恢复使用 settings.Token

func connectGhostTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	// 1. 建立纯净的 WebSocket 连接
	wsConn, err := dialCleanWebSocket(settings)
	if err != nil { return nil, err }

	// =========================================================
	// 【关键修正】恢复动态配置
	// 此时 settings.Token 里面存的就是 C++ 传过来的明文 Secret Key
	// =========================================================
	
	// 2. 发送幽灵握手包 (使用动态密钥)
	err = sendGhostHandshake(wsConn, target, settings.Token, payload)
	
	if err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// 发送幽灵协议握手包
func sendGhostHandshake(wsConn *websocket.Conn, target string, secretKey string, payload []byte) error {
	// A. 准备时间戳 (8 bytes BigEndian) - 秒级
	ts := time.Now().Unix() 
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))

	// B. 准备目标地址 (XOR 加密)
	// 密钥 = SecretKey + Timestamp字符串
	xorKeyStr := fmt.Sprintf("%s%d", secretKey, ts)
	xorKey := []byte(xorKeyStr)
	targetBytes := []byte(target)
	encryptedTarget := make([]byte, len(targetBytes))
	for i, b := range targetBytes {
		encryptedTarget[i] = b ^ xorKey[i%len(xorKey)]
	}

	// C. 准备目标长度 (2 bytes)
	targetLen := uint16(len(encryptedTarget))
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, targetLen)

	// D. 计算 HMAC-SHA256 签名 (32 bytes)
	// 签名内容 = TS(8) + Len(2) + EncryptedTarget(N)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(tsBytes)
	mac.Write(lenBytes)
	mac.Write(encryptedTarget)
	signature := mac.Sum(nil)

	// E. 拼装大包
	// 结构: [TS 8] + [Sig 32] + [Len 2] + [EncTarget N] + [Payload ...]
	totalLen := 8 + 32 + 2 + len(encryptedTarget) + len(payload)
	packet := make([]byte, totalLen)

	cursor := 0
	copy(packet[cursor:], tsBytes); cursor += 8
	copy(packet[cursor:], signature); cursor += 32
	copy(packet[cursor:], lenBytes); cursor += 2
	copy(packet[cursor:], encryptedTarget); cursor += len(encryptedTarget)
	if len(payload) > 0 {
		copy(packet[cursor:], payload)
	}

	// 发送二进制消息
	return wsConn.WriteMessage(websocket.BinaryMessage, packet)
}

// 拨号器
func dialCleanWebSocket(settings ProxySettings) (*websocket.Conn, error) {
	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)
	
	requestHeader := http.Header{}
	requestHeader.Add("Host", host)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		},
		HandshakeTimeout: 5 * time.Second,
	}

	if settings.ForwarderSettings != nil && settings.ForwarderSettings.Socks5Address != "" {
		proxyAddrStr := settings.ForwarderSettings.Socks5Address
		if !strings.Contains(proxyAddrStr, "://") { proxyAddrStr = "socks5://" + proxyAddrStr }
		proxyURL, _ := url.Parse(proxyAddrStr)
		var auth *proxy.Auth
		if proxyURL.User != nil {
			auth = new(proxy.Auth)
			auth.User = proxyURL.User.Username()
			if p, ok := proxyURL.User.Password(); ok { auth.Password = p }
		}
		socks5Dialer, _ := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		dialer.NetDial = socks5Dialer.Dial
	} else if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

// 直接管道转发
func pipeDirect(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	
	// WS -> Local
	go func() {
		for {
			mt, r, err := ws.NextReader()
			if err != nil { break }
			if mt == websocket.BinaryMessage { 
				io.Copy(local, r)
			}
		}
		local.Close()
	}()
	
	// Local -> WS
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

// --- 辅助函数 ---
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host = addr; port = "443"; err = nil }; return }
