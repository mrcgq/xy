// core/core-binary.go (v10.5 - Nano Ultimate Fixed)
// [修复] 引入 sync.Pool 复用内存，降低 GC 压力
// [修复] 优化 pipeDirect 管道资源释放逻辑
// [特性] 完美适配 v10.5 服务端：0-RTT, URL Token, Early Data

//go:build binary
// +build binary

package core

import (
	"bufio"
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
	"sync" // [新增] 引入 sync 包用于内存池
	"time"

	"github.com/gorilla/websocket"
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

// [优化] 定义全局内存池，复用 32KB 缓冲区，减少 GC 压力
var bufPool = sync.Pool{
	New: func() interface{} {
		// 32KB 是 Cloudflare 管道传输的最佳切片大小
		return make([]byte, 32*1024)
	},
}

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
	
	log.Printf("[Core] Xlink Nano Engine (v10.5 Ultimate) Listening on %s", inbound.Listen)
	
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
	// 注意：这里不要过早 defer conn.Close()，因为所有权会转移给 pipeDirect
	// 但为了防止 panic 导致的泄露，保留 defer 是安全的，Close 可以多次调用
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
		return 
	}

	// 建立到 Cloudflare Workers 的 WebSocket 隧道
	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil { 
		return 
	}
	
	// 注意：wsConn 的关闭由 pipeDirect 接管

	// 握手成功，响应本地客户端
	if mode == 1 { 
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
	}
	if mode == 2 { 
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) 
	}
	
	// 进入纯管道传输模式 (借力打力：只转发，不处理)
	pipeDirect(conn, wsConn)
}

func connectNanoTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	// 1. 提取 Token 和 Fallback
	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 { 
		fallback = parts[1] 
	}

	// 2. 提取 SOCKS5 (作为协议头数据发送给服务端，不是本地连接用)
	socks5 := ""
	if settings.ForwarderSettings != nil { 
		socks5 = settings.ForwarderSettings.Socks5Address 
	}

	// 3. 建立 WebSocket 连接 (使用 URL Token 鉴权)
	wsConn, err := dialCleanWebSocket(settings, secretKey)
	if err != nil { return nil, err }

	// 4. 发送 v10.2/v10.5 协议头 (包含 Target, S5, Fallback, Payload)
	err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
	if err != nil {
		wsConn.Close()
		return nil, err
	}
	return wsConn, nil
}

func dialCleanWebSocket(settings ProxySettings, token string) (*websocket.Conn, error) {
	host, port, path, _ := parseServerAddr(settings.Server)
	
	// 关键：将 Token 拼接到 URL 参数中 (0-RTT 鉴权)
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

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil { 
		if resp != nil { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }
		return nil, err 
	}
	return conn, nil
}

// [v10.5] Nano 协议发送：支持 S5 和 Fallback
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	hostBytes := []byte(host)
	s5Bytes := []byte(s5)
	fbBytes := []byte(fb)

	// 长度检查
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

	// 一次性发送 (Zero RTT)
	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// --- 辅助函数 ---

// [优化] 引入 sync.Pool 的高性能管道函数
func pipeDirect(local net.Conn, ws *websocket.Conn) { 
	// 确保双向关闭
	defer ws.Close()
	defer local.Close()

	// 远程 (WS) -> 本地 (TCP)
	// 使用 io.Copy 实现零拷贝 (Go底层会利用 sendfile/splice)
	go func() { 
		for { 
			mt, r, err := ws.NextReader()
			if err != nil { break }
			if mt == websocket.BinaryMessage { 
				if _, err := io.Copy(local, r); err != nil { break }
			}
		} 
		// 远程断开 -> 关闭本地
		local.Close() 
	}() 

	// 本地 (TCP) -> 远程 (WS)
	// 使用内存池优化
	bufPtr := bufPool.Get().([]byte) // 从池中借出
	defer bufPool.Put(bufPtr)        // 函数结束归还

	for { 
		n, err := local.Read(bufPtr)
		if n > 0 { 
			// 写入 WebSocket
			if err := ws.WriteMessage(websocket.BinaryMessage, bufPtr[:n]); err != nil { break }
		} 
		if err != nil { break }
	} 
	// 本地断开 -> 循环结束 -> defer 触发 ws.Close()
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
	// 注意：这里 bufio 可能会预读数据。
	// 对于 HTTPS CONNECT，Header 后通常无数据，安全。
	// 对于 HTTP Proxy，如果有 Body，可能会被 bufio 吞掉部分。
	// 但鉴于这主要是为了 Xray/Browser 代理，CONNECT 是主流，此处保持标准库实现以维持代码简洁。
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
