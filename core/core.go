// core/core.go (v1.3 - Advanced Behavior Mimicry)
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

// JsonEnvelope 定义了伪装用的JSON结构体
type JsonEnvelope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	TS   int64  `json:"ts"`
	Data string `json:"data"` // Base64 编码的原始数据
}

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

// wrapAsJson 将原始二进制数据封装成JSON消息
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

// unwrapFromJson 从JSON消息中解析出原始二进制数据
func unwrapFromJson(rawMsg []byte) ([]byte, error) {
	var envelope JsonEnvelope
	if err := json.Unmarshal(rawMsg, &envelope); err != nil {
		return nil, fmt.Errorf("not a valid json envelope: %w", err)
	}
	// 只有当类型是我们约定的类型时才解码
	if envelope.Type != "sync_data" {
		// 忽略 ping/pong 等心跳消息
		return nil, fmt.Errorf("not a sync_data type message: %s", envelope.Type)
	}
	return base64.StdEncoding.DecodeString(envelope.Data)
}

// StartInstance 是内核库的入口函数
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	loadChinaListsForRouter()
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		log.Printf("[Error] Listen failed on %s: %v", inbound.Listen, err)
		return nil, err
	}
	log.Printf("[Inbound] Listening on %s (%s)", inbound.Listen, inbound.Tag)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("[Core] Listener closed on %s: %v", inbound.Listen, err)
				break
			}
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
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	var target string
	var err error
	var firstFrame []byte
	var mode int
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
		log.Printf("[%s] Protocol error: %v", inboundTag, err)
		return
	}
	outboundTag := route(target, inboundTag)
	log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeBuf); err != nil {
		return "", err
	}
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01})
		return "", errors.New("unsupported SOCKS5 command")
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
		return "", errors.New("bad addr type")
	}
	portBytes := make([]byte, 2)
	io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Printf("[%s] SOCKS5: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)
	return target, nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", nil, 0, err
	}
	target := req.Host
	mode := 2
	if req.Method == "CONNECT" {
		log.Printf("[%s] HTTP CONNECT: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)
		return target, nil, mode, nil
	}
	log.Printf("[%s] HTTP Proxy: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)
	mode = 3
	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), mode, nil
}

func route(target, inboundTag string) string {
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}
	for _, rule := range globalConfig.Routing.Rules {
		if len(rule.InboundTag) > 0 {
			match := false
			for _, t := range rule.InboundTag {
				if t == inboundTag {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if len(rule.Domain) > 0 {
			for _, d := range rule.Domain {
				if strings.Contains(host, d) {
					return rule.OutboundTag
				}
			}
		}
		if rule.GeoIP == "cn" {
			if isChinaIPForRouter(net.ParseIP(host)) {
				return rule.OutboundTag
			}
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) {
				return rule.OutboundTag
			}
		}
	}
	if globalConfig.Routing.DefaultOutbound != "" {
		return globalConfig.Routing.DefaultOutbound
	}
	return "direct"
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	outbound, ok := findOutbound(outboundTag)
	if !ok {
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
	if err != nil {
		log.Printf("Tunnel failed for %s: %v", target, err)
	}
}

const (
	modeSOCKS5      = 1
	modeHTTPConnect = 2
	modeHTTPProxy   = 3
)

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, mode int) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		if mode == modeSOCKS5 {
			local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		}
		if mode == modeHTTPConnect {
			local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return err
	}
	defer remote.Close()
	if mode == modeSOCKS5 {
		local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	if mode == modeHTTPConnect {
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
		if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) }
		if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
		return err
	}
	defer wsConn.Close()

	noiseCount := mathrand.Intn(4) + 1
	for i := 0; i < noiseCount; i++ {
		noiseSize := mathrand.Intn(201) + 50
		noise := make([]byte, noiseSize)
		rand.Read(noise)
		if err := wsConn.WriteMessage(websocket.BinaryMessage, noise); err != nil {
			log.Printf("Warning: failed to send noise packet: %v", err)
		}
		time.Sleep(time.Duration(mathrand.Intn(51)+10) * time.Millisecond)
	}
	connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	jsonHandshake, err := wrapAsJson([]byte(connectMsg))
	if err != nil {
		return fmt.Errorf("failed to wrap handshake in json: %w", err)
	}
	if err := wsConn.WriteMessage(websocket.TextMessage, jsonHandshake); err != nil {
		return err
	}
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return err
	}
	okPayload, err := unwrapFromJson(msg)
	if err != nil || string(okPayload) != "X-LINK-OK" {
		return fmt.Errorf("handshake failed or unexpected response: %s", msg)
	}
	if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) }
	if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	done := make(chan bool, 2)

	go func() {
		lastSendTime := time.Now()
		heartbeatTicker := time.NewTicker(15 * time.Second)
		defer heartbeatTicker.Stop()
		buf := make([]byte, 32*1024)
		for {
			local.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := local.Read(buf)
			if n > 0 {
				lastSendTime = time.Now()
				remainingData := buf[:n]
				for len(remainingData) > 0 {
					chunkSize := mathrand.Intn(2501) + 500
					if chunkSize > len(remainingData) {
						chunkSize = len(remainingData)
					}
					chunk := remainingData[:chunkSize]
					remainingData = remainingData[chunkSize:]
					jsonData, err := wrapAsJson(chunk)
					if err != nil { continue }
					if err := wsConn.WriteMessage(websocket.TextMessage, jsonData); err != nil {
						done <- true
						return
					}
					if len(remainingData) > 0 {
						time.Sleep(time.Duration(mathrand.Intn(46)+5) * time.Millisecond)
					}
				}
			}
			if err != nil {
				if os.IsTimeout(err) {
					select {
					case <-heartbeatTicker.C:
						if time.Since(lastSendTime) > 15*time.Second {
							pingEnvelope := JsonEnvelope{
								ID:   fmt.Sprintf("ping_%x", time.Now().Unix()),
								Type: "ping",
								TS:   time.Now().UnixMilli(),
								Data: "",
							}
							pingJson, _ := json.Marshal(pingEnvelope)
							if err := wsConn.WriteMessage(websocket.TextMessage, pingJson); err != nil {
								done <- true
								return
							}
							lastSendTime = time.Now()
						}
					default:
					}
					continue
				}
				wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				done <- true
				return
			}
		}
	}()

	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil {
				local.Close()
				done <- true
				return
			}
			payload, err := unwrapFromJson(msg)
			if err != nil {
				continue
			}
			if _, err := local.Write(payload); err != nil {
				done <- true
				return
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
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host}
	dialer := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{settings.Token}}
	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
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

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func isChinaIPForRouter(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		val := ipToUint32(ip4)
		chinaIPRangesMu.RLock()
		defer chinaIPRangesMu.RUnlock()
		for _, r := range chinaIPRanges {
			if val >= r.start && val <= r.end {
				return true
			}
		}
	} else if ip16 := ip.To16(); ip16 != nil {
		var val [16]byte
		copy(val[:], ip16)
		chinaIPV6RangesMu.RLock()
		defer chinaIPV6RangesMu.RUnlock()
		for _, r := range chinaIPV6Ranges {
			if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 {
				return true
			}
		}
	}
	return false
}

func loadChinaListsForRouter() {
	loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false)
	loadIPListForRouter("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true)
}

func loadIPListForRouter(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) {
	file, err := os.Open(filepath.Join(getExeDir(), filename))
	if err != nil {
		return
	}
	defer file.Close()
	var rangesV4 []ipRange
	var rangesV6 []ipRangeV6
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}
		if isV6 {
			var s, e [16]byte
			copy(s[:], startIP.To16())
			copy(e[:], endIP.To16())
			rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e})
		} else {
			s, e := ipToUint32(startIP), ipToUint32(endIP)
			if s > 0 && e > 0 {
				rangesV4 = append(rangesV4, ipRange{start: s, end: e})
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if isV6 {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6))
	} else {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4))
	}
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	return
}```

---

### **2. `X-Link 服务器 (v1.6 - Advanced Behavior Mimicry)` - 完整无省略代码版**

**文件: `x私有协议 去指纹版.js`**

```javascript
/**
 * X-Link 服务器 (v1.6 - Advanced Behavior Mimicry)
 * 协议特征：JSON内容伪装 + 高级行为伪装
 * 升级：
 * 1. [行为伪装] 实现数据帧分片和随机延迟，模拟真实应用的数据传输节奏。
 * 2. [行为伪装] 支持并响应客户端的 "ping" 心跳消息，维持连接活性假象。
 * 3. 保持了 v1.5 的所有伪装和安全特性。
 */

// ================= [ 配置区域 ] =================
const SECRET_KEY = "my-secret-key-888";  
const AUTH_PASSWORD = "my-password";     
const DEFAULT_FALLBACK = "proxy.xxxxxxxx.tk:50001"; 
// ===============================================

import { connect } from 'cloudflare:sockets';

// 辅助函数：将 ArrayBuffer 转换为 Base64 字符串
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function wrapInJson(data) { // data is Uint8Array
    const id = `msg_${Math.random().toString(16).slice(2, 10)}`;
    const envelope = {
        id: id,
        type: 'sync_data',
        ts: Date.now(),
        data: arrayBufferToBase64(data)
    };
    return JSON.stringify(envelope);
}

function unwrapFromJson(jsonString) {
    try {
        const envelope = JSON.parse(jsonString);
        if (envelope.type === 'ping') {
            return { isHeartbeat: true, id: envelope.id };
        }
        if (envelope.type === 'sync_data' && envelope.data) {
            const decodedStr = atob(envelope.data);
            const bytes = new Uint8Array(decodedStr.length);
            for (let i = 0; i < decodedStr.length; i++) {
                bytes[i] = decodedStr.charCodeAt(i);
            }
            return { payload: bytes };
        }
    } catch (e) {}
    return null;
}

function xorDecrypt(input, key) {
  let output = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    output[i] = input[i] ^ key.charCodeAt(i % key.length);
  }
  return output;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new Response('X-Link 网关在线 (v1.6)', { status: 200 });
      }
      const rawToken = request.headers.get('Sec-WebSocket-Protocol') || "";
      let dynamicFallbackIP = null;
      if (!rawToken) { return new Response('缺少令牌', { status: 401 }); }
      try {
        const decoded = atob(rawToken);
        const decodedBytes = new Uint8Array(decoded.length);
        for(let i=0; i<decoded.length; i++) decodedBytes[i] = decoded.charCodeAt(i);
        const decryptedBytes = xorDecrypt(decodedBytes, SECRET_KEY);
        const decryptedStr = new TextDecoder().decode(decryptedBytes);
        const config = JSON.parse(decryptedStr); 
        if (config.p !== AUTH_PASSWORD) return new Response('认证失败', { status: 403 });
        if (config.fb && config.fb.trim() !== "") {
          dynamicFallbackIP = config.fb.trim().replace(/^https?:\/\//, '');
        }
      } catch (e) { return new Response('令牌错误', { status: 400 }); }
      const webSocketPair = new WebSocketPair();
      const [client, server] = Object.values(webSocketPair);
      server.accept();
      handleSession(server, dynamicFallbackIP);
      return new Response(null, { status: 101, webSocket: client });
    } catch (err) { return new Response('内部服务器错误', { status: 500 }); }
  },
};

async function handleSession(webSocket, dynamicFallbackIP) {
    let remoteSocket = null;
    let state = 'HANDSHAKING';

    const handshakeTimeout = setTimeout(() => {
        if (state === 'HANDSHAKING') {
            try {
                const fakeError = { error: "Authentication failed", code: 401, message: "Invalid session token or handshake timeout." };
                webSocket.send(JSON.stringify(fakeError));
                webSocket.close(1000, "Fake Auth Error");
            } catch (e) {}
        }
    }, 5000);

    const closeAll = () => {
        clearTimeout(handshakeTimeout);
        try { webSocket.close(1011, "Internal Error"); } catch (err) {}
        try { remoteSocket?.close(); } catch (err) {}
    };
    
    webSocket.addEventListener('message', async (event) => {
        if (state === 'RELAYING') {
            if (typeof event.data === 'string') {
                const unwrapped = unwrapFromJson(event.data);
                if (unwrapped) {
                    if (unwrapped.isHeartbeat) {
                        const pongEnvelope = { id: unwrapped.id, type: 'pong', ts: Date.now(), data: '' };
                        webSocket.send(JSON.stringify(pongEnvelope));
                        return;
                    }
                    if (unwrapped.payload && remoteSocket && remoteSocket.writable) {
                        const writer = remoteSocket.writable.getWriter();
                        writer.write(unwrapped.payload).catch(err => {});
                        writer.releaseLock();
                    }
                }
            }
            return; 
        }

        try {
            if (event.data instanceof ArrayBuffer) { return; }
            if (typeof event.data !== 'string') { return; }

            const rawHandshakeBytes = unwrapFromJson(event.data)?.payload;
            if (!rawHandshakeBytes) { return; }

            const handshakeText = new TextDecoder().decode(rawHandshakeBytes);
            if (!handshakeText.startsWith('X-LINK:')) { return; }

            clearTimeout(handshakeTimeout);
            state = 'RELAYING';

            const separatorIndex = handshakeText.indexOf('|');
            if (separatorIndex === -1) { throw new Error("Handshake format error"); }

            const targetAddress = handshakeText.substring(7, separatorIndex);
            const firstFrameBase64 = handshakeText.substring(separatorIndex + 1);
            
            const target = parseAddress(targetAddress);
            
            const attempts = [];
            attempts.push({ name: 'Direct', host: target.host, port: target.port });
            if (dynamicFallbackIP) {
                const fb = parseAddress(dynamicFallbackIP);
                attempts.push({ name: 'ClientFallback', host: fb.host, port: fb.port });
            } else if (DEFAULT_FALLBACK) {
                const fb = parseAddress(DEFAULT_FALLBACK);
                attempts.push({ name: 'DefaultFallback', host: fb.host, port: fb.port });
            }

            let connectionSuccessful = false;
            for (const attempt of attempts) {
                try {
                    remoteSocket = connect({ hostname: attempt.host, port: attempt.port });
                    await remoteSocket.opened;
                    connectionSuccessful = true;
                    
                    if (firstFrameBase64.length > 0) {
                        const firstFrameStr = atob(firstFrameBase64);
                        const firstFrameBytes = new Uint8Array(firstFrameStr.length);
                        for (let i = 0; i < firstFrameStr.length; i++) {
                            firstFrameBytes[i] = firstFrameStr.charCodeAt(i);
                        }
                        const writer = remoteSocket.writable.getWriter();
                        await writer.write(firstFrameBytes);
                        writer.releaseLock();
                    }
                    
                    const okBytes = new TextEncoder().encode('X-LINK-OK');
                    webSocket.send(wrapInJson(okBytes));
                    
                    (async () => {
                        const reader = remoteSocket.readable.getReader();
                        try {
                            while (true) {
                                const { done, value } = await reader.read(); // value is Uint8Array
                                if (done) break;
                                
                                let remainingData = value;
                                while (remainingData.length > 0) {
                                    let chunkSize = Math.floor(Math.random() * 2501) + 500;
                                    if (chunkSize > remainingData.length) {
                                        chunkSize = remainingData.length;
                                    }
                                    const chunk = remainingData.slice(0, chunkSize);
                                    remainingData = remainingData.slice(chunkSize);
                                    if (webSocket.readyState === 1) {
                                        webSocket.send(wrapInJson(chunk));
                                    } else {
                                        break;
                                    }
                                    if (remainingData.length > 0) {
                                        await new Promise(resolve => setTimeout(resolve, Math.random() * 45 + 5));
                                    }
                                }
                            }
                        } catch(e) {} finally {
                           closeAll();
                        }
                    })();
                    break;
                } catch (err) {
                    try { remoteSocket?.close(); } catch {}
                    if (attempts.indexOf(attempt) === attempts.length - 1) {
                        throw new Error("All connection attempts failed.");
                    }
                }
            }
            if (!connectionSuccessful) {
                throw new Error("Could not establish remote connection.");
            }
        } catch (err) {
            closeAll();
        }
    });
    webSocket.addEventListener('close', closeAll);
    webSocket.addEventListener('error', closeAll);
}

function parseAddress(addrStr) {
    if (!addrStr) throw new Error('Empty address');
    addrStr = addrStr.trim();
    const match = addrStr.match(/^\[(.+)\]:(\d+)$/);
    if (match) return { host: match[1], port: parseInt(match[2]) };
    if (addrStr.startsWith('[') && addrStr.endsWith(']')) return { host: addrStr.slice(1, -1), port: 443 };
    const parts = addrStr.split(':');
    if (parts.length > 1 && /^\d+$/.test(parts[parts.length - 1])) {
        const port = parseInt(parts.pop());
        const host = parts.join(':');
        return { host, port };
    } 
    return { host: addrStr, port: 443 };
}
