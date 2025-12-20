

// core/core-binary.go (v8.1 - Fix Compile Error)
// 修复: 补齐缺失的 "bufio" 引用

//go:build binary
// +build binary

package core

import (
	"bufio" // <--- [修复] 补齐了这个缺失的包
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
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// --- 结构定义 (不变) ---
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"`; ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }
var ( globalConfig Config; proxySettingsMap = make(map[string]ProxySettings) )

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ======================== 入口函数 (不变) ========================
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	log.Printf("[Core] Xlink PhantomFlow Engine (v8.1) Listening on %s", inbound.Listen)
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
	
	var target string; var err error; var firstFrame []byte; var mode int
	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil { return }

	wsConn, err := connectPhantomTunnel(target, "proxy", firstFrame)
	if err != nil { 
        log.Printf("[ERROR] Failed to connect Phantom Tunnel: %v", err)
        return 
    }

	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	pipeDirect(conn, wsConn)
}

func connectPhantomTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	wsConn, err := dialCleanWebSocket(settings)
	if err != nil { return nil, err }

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 { fallback = parts[1] }
    socks5 := ""
    if settings.ForwarderSettings != nil { socks5 = settings.ForwarderSettings.Socks5Address }

	err = sendPhantomHandshake(wsConn, target, secretKey, payload, socks5, fallback)
	if err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// [核心] v8.0 Phantom 握手协议
func sendPhantomHandshake(wsConn *websocket.Conn, target string, secretKey string, payload []byte, socks5 string, fallback string) error {
	
	// --- 1. 准备核心数据 ---
	ts := time.Now().UnixNano() / 1e6 
	tsBytes := make([]byte, 8); binary.BigEndian.PutUint64(tsBytes, uint64(ts))

	nonce := rand.Uint32()
	nonceBytes := make([]byte, 4); binary.BigEndian.PutUint32(nonceBytes, nonce)

	// --- 2. 准备动态填充 (Dynamic Padding) ---
	paddingLen := byte(rand.Intn(128)) 
	padding := make([]byte, paddingLen)
	rand.Read(padding)

	// --- 3. 准备加密数据块 ---
	targetBytes := []byte(target)
	socks5Bytes := []byte(socks5)
	fallbackBytes := []byte(fallback)
	dataBlob := append(targetBytes, socks5Bytes...)
	dataBlob = append(dataBlob, fallbackBytes...)
	
	xorKeyStr := fmt.Sprintf("%s%d%d", secretKey, ts, nonce)
	xorKey := []byte(xorKeyStr)
	encryptedData := make([]byte, len(dataBlob))
	for i, b := range dataBlob {
		encryptedData[i] = b ^ xorKey[i%len(xorKey)]
	}

	// Lengths
	targetLenBytes := make([]byte, 2); binary.BigEndian.PutUint16(targetLenBytes, uint16(len(targetBytes)))
	socks5LenBytes := make([]byte, 2); binary.BigEndian.PutUint16(socks5LenBytes, uint16(len(socks5Bytes)))
	fallbackLenBytes := make([]byte, 2); binary.BigEndian.PutUint16(fallbackLenBytes, uint16(len(fallbackBytes)))
	lenBlob := append(targetLenBytes, socks5LenBytes...)
	lenBlob = append(lenBlob, fallbackLenBytes...) 

	// --- 4. 计算 HMAC ---
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(tsBytes)
	mac.Write(nonceBytes)
	mac.Write([]byte{paddingLen})
	mac.Write(padding)
	mac.Write(lenBlob)
	mac.Write(encryptedData)
	signature := mac.Sum(nil)

	// --- 5. 组装真实协议头 ---
	headerBuf := new(bytes.Buffer)
	headerBuf.Write(tsBytes)       
	headerBuf.Write(nonceBytes)    
	headerBuf.Write(signature)     
	headerBuf.WriteByte(paddingLen)
	headerBuf.Write(padding)       
	headerBuf.Write(lenBlob)       
	headerBuf.Write(encryptedData)
	realHeader := headerBuf.Bytes()

// --- 6. 构造前置噪声 (Phantom Noise - 确定性动态长度) ---
	magicByte := byte(rand.Intn(256))
	
	// [算法] 必须与 JS 端 PHANTOM_CONFIG 完全一致
	// 公式: Len = (Magic * 17 + 13) % 71 + 20
	// 这样 JS 端只需要读第一个字节，就知道接下来要跳过多少字节的噪声
	noiseLen := int(magicByte)*17 + 13
	noiseLen = noiseLen % 71
	noiseLen = noiseLen + 20
	
	noiseData := make([]byte, noiseLen)
	rand.Read(noiseData)

	prefixBuf := new(bytes.Buffer)
	prefixBuf.WriteByte(magicByte) // 写入 Magic Byte
	prefixBuf.Write(noiseData)     // 写入计算出的长度的噪声
	noisePacket := prefixBuf.Bytes()

	// --- 7. 发送策略：分裂传输 ---
	if err := wsConn.WriteMessage(websocket.BinaryMessage, noisePacket); err != nil { return err }
	time.Sleep(time.Duration(10 + rand.Intn(20)) * time.Millisecond)

	if err := wsConn.WriteMessage(websocket.BinaryMessage, realHeader); err != nil { return err }

	if len(payload) > 0 {
		time.Sleep(time.Duration(20 + rand.Intn(40)) * time.Millisecond)
		if err := wsConn.WriteMessage(websocket.BinaryMessage, payload); err != nil { return err }
	}

	return nil
}

// --- 辅助函数 ---
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

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host = addr; port = "443"; err = nil }; return }









