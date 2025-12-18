// core/core-binary.go (v7.3 - Anti-Replay & Traffic Shaping)
// 适配服务端 v7.3 协议

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
	"math/rand" // [新增] 用于生成 Nonce 和随机延迟
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// --- 结构定义 (保持不变) ---
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"`; ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }
var ( globalConfig Config; proxySettingsMap = make(map[string]ProxySettings) )

// [新增] 初始化随机种子 (适配低版本 Go)
func init() {
	rand.Seed(time.Now().UnixNano())
}

// ======================== 入口函数 ========================
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	log.Printf("[Core] Xlink Ghost Engine (v7.3) Listening on %s", inbound.Listen)
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
	// 预读取第一个字节判断协议
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	
	var target string; var err error; var firstFrame []byte; var mode int
	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil { return }

	// 连接 WebSocket 隧道
	wsConn, err := connectGhostTunnel(target, "proxy", firstFrame)
	if err != nil { 
        log.Printf("[ERROR] Failed to connect Ghost Tunnel: %v", err)
        return 
    }

	// 响应本地客户端 (握手成功)
	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	pipeDirect(conn, wsConn)
}

func connectGhostTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found for tag: " + outboundTag) }

	wsConn, err := dialCleanWebSocket(settings)
	if err != nil { return nil, err }

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 {
		fallback = parts[1]
	}
    
    socks5 := ""
    if settings.ForwarderSettings != nil {
        socks5 = settings.ForwarderSettings.Socks5Address
    }

	// 发送 v7.3 握手包
	err = sendGhostHandshake(wsConn, target, secretKey, payload, socks5, fallback)
	if err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// [核心修改] v7.3 协议握手包 (防重放 + 流量整形)
func sendGhostHandshake(wsConn *websocket.Conn, target string, secretKey string, payload []byte, socks5 string, fallback string) error {
	// 1. 准备 Timestamp (8 bytes, Milliseconds)
	ts := time.Now().UnixNano() / 1e6 
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))

	// 2. [新增] 准备 Nonce (4 bytes)
	nonce := rand.Uint32()
	nonceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceBytes, nonce)

	// 3. 准备数据块并加密
	targetBytes := []byte(target)
	socks5Bytes := []byte(socks5)
	fallbackBytes := []byte(fallback)

	dataBlob := append(targetBytes, socks5Bytes...)
	dataBlob = append(dataBlob, fallbackBytes...)
	
	// [修改] XOR Key = Secret + TS + Nonce
	xorKeyStr := fmt.Sprintf("%s%d%d", secretKey, ts, nonce)
	xorKey := []byte(xorKeyStr)
	encryptedData := make([]byte, len(dataBlob))
	for i, b := range dataBlob {
		encryptedData[i] = b ^ xorKey[i%len(xorKey)]
	}

	// 4. 准备长度字段 (6 bytes)
	targetLenBytes := make([]byte, 2); binary.BigEndian.PutUint16(targetLenBytes, uint16(len(targetBytes)))
	socks5LenBytes := make([]byte, 2); binary.BigEndian.PutUint16(socks5LenBytes, uint16(len(socks5Bytes)))
	fallbackLenBytes := make([]byte, 2); binary.BigEndian.PutUint16(fallbackLenBytes, uint16(len(fallbackBytes)))

	lenBlob := append(targetLenBytes, socks5LenBytes...)
	lenBlob = append(lenBlob, fallbackLenBytes...) 

	// 5. 计算 HMAC 签名
	// 签名覆盖: TS(8) + Nonce(4) + LenBlob(6) + EncryptedData(N)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(tsBytes)
	mac.Write(nonceBytes) // [新增]
	mac.Write(lenBlob)
	mac.Write(encryptedData)
	signature := mac.Sum(nil)

	// 6. 拼装协议头
	// 结构 v7.3: [TS 8] + [Nonce 4] + [Sig 32] + [LenBlob 6] + [EncData N]
	headerBuf := new(bytes.Buffer)
	headerBuf.Write(tsBytes)
	headerBuf.Write(nonceBytes) // [新增]
	headerBuf.Write(signature)
	headerBuf.Write(lenBlob)
	headerBuf.Write(encryptedData)
	
	headerBytes := headerBuf.Bytes()

	// 7. [新增] 流量整形 (Split-The-Packet)
	// 策略: 先发送头部，Sleep 随机时间，再发送 Payload
	
	// 发送头部
	err := wsConn.WriteMessage(websocket.BinaryMessage, headerBytes)
	if err != nil {
		return err
	}

	// 如果有真实负载 (Payload)，则进行伪装发送
	if len(payload) > 0 {
		// 随机延迟 10 - 40ms，模拟网络波动或浏览器处理时间，欺骗 DPI
		jitter := time.Duration(10 + rand.Intn(30)) * time.Millisecond
		time.Sleep(jitter)

		err = wsConn.WriteMessage(websocket.BinaryMessage, payload)
		if err != nil {
			return err
		}
	}

	return nil
}

func dialCleanWebSocket(settings ProxySettings) (*websocket.Conn, error) {
	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)
	requestHeader := http.Header{}
	requestHeader.Add("Host", host)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	dialer := websocket.Dialer{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: host }, HandshakeTimeout: 5 * time.Second }
	
	if settings.ForwarderSettings != nil && settings.ForwarderSettings.Socks5Address != "" {
		proxyAddrStr := settings.ForwarderSettings.Socks5Address
		if !strings.Contains(proxyAddrStr, "://") { proxyAddrStr = "socks5://" + proxyAddrStr }
		proxyURL, _ := url.Parse(proxyAddrStr)
		var auth *proxy.Auth
		if proxyURL.User != nil { auth = new(proxy.Auth); auth.User = proxyURL.User.Username(); if p, ok := proxyURL.User.Password(); ok { auth.Password = p } }
		socks5Dialer, _ := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		dialer.NetDial = socks5Dialer.Dial
	} else if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) { _, p, _ := net.SplitHostPort(addr); return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second) }
	}
	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil { if resp != nil { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }; return nil, err }
	return conn, nil
}

func pipeDirect(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	go func() { for { mt, r, err := ws.NextReader(); if err != nil { break }; if mt == websocket.BinaryMessage { io.Copy(local, r) } }; local.Close() }()
	buf := make([]byte, 32*1024)
	for { n, err := local.Read(buf); if n > 0 { err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); if err != nil { break } }; if err != nil { break } }
}

// --- 辅助函数 ---
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host = addr; port = "443"; err = nil }; return }
