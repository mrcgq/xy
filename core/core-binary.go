// core/core-binary.go (v12.1 - Hydra Strategy Edition)
// [基座] v12.0 Hydra (节点池)
// [新增] 策略调度引擎 (Random / Round-Robin / Sticky Hash)
// [状态] 物理性能无损，逻辑维度升级

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"crypto/md5" // [v12.1] Hash 策略需要
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
	"sync"
	"sync/atomic" // [v12.1] RR 策略需要
	"time"

	"github.com/gorilla/websocket"
)

// 全局计数器 (用于轮询策略)
var globalRRIndex uint64

// --- 结构定义 ---
type ProxySettings struct { 
	Server     string   `json:"server"`
	ServerPool []string `json:"server_pool"`
	Strategy   string   `json:"strategy"` // [v12.1] 策略字段: random, rr, hash
	ServerIP   string   `json:"server_ip"` 
	Token      string   `json:"token"` 
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` 
}

type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }

var ( 
	globalConfig Config
	proxySettingsMap = make(map[string]ProxySettings)
)

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 32*1024) },
}

// ======================== 核心入口 ========================

func StartInstance(configContent []byte) (net.Listener, error) {
	rand.Seed(time.Now().UnixNano())
	proxySettingsMap = make(map[string]ProxySettings)
	
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds()
	
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	
	mode := "Single Node"
	if len(globalConfig.Outbounds) > 0 {
		var s ProxySettings
		json.Unmarshal(globalConfig.Outbounds[0].Settings, &s)
		if len(s.ServerPool) > 1 {
			mode = fmt.Sprintf("Hydra Pool (%d nodes, Strategy: %s)", len(s.ServerPool), s.Strategy)
		}
	}
	log.Printf("[Core] Xlink Hydra Engine (v12.1) Listening on %s [%s]", inbound.Listen, mode)
	
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
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	var target string
	var err error
	var firstFrame []byte
	var mode int 
	switch buf[0] {
	case 0x05: target, err = handleSOCKS5(conn, inboundTag); mode = 1
	default: target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil { return }

	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil { return }

	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	pipeDirect(conn, wsConn)
}

// [v12.1 核心] 智能调度器
func connectNanoTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 { fallback = parts[1] }
	socks5 := ""
	if settings.ForwarderSettings != nil { socks5 = settings.ForwarderSettings.Socks5Address }

	// ---------------------- 战术调度逻辑 ----------------------
	targetServer := settings.Server // 默认单节点
	if len(settings.ServerPool) > 0 {
		poolLen := uint64(len(settings.ServerPool))
		strategy := settings.Strategy

		switch strategy {
		case "rr": // 🚀 加特林模式 (Round Robin)
			idx := atomic.AddUint64(&globalRRIndex, 1)
			targetServer = settings.ServerPool[idx%poolLen]

		case "hash": // 🎯 狙击模式 (Sticky Hash)
			// 计算目标域名的 MD5，确保同一网站始终命中同一节点
			h := md5.Sum([]byte(target))
			hashVal := binary.BigEndian.Uint64(h[:8])
			targetServer = settings.ServerPool[hashVal%poolLen]

		default: // ⚔️ 混沌模式 (Random) - 默认
			targetServer = settings.ServerPool[rand.Intn(int(poolLen))]
		}
	}
	// ---------------------------------------------------------

	wsConn, err := dialCleanWebSocket(targetServer, settings.ServerIP, secretKey)
	if err != nil { return nil, err }

	err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
	if err != nil { wsConn.Close(); return nil, err }
	return wsConn, nil
}

func dialCleanWebSocket(serverAddr, serverIP, token string) (*websocket.Conn, error) {
	host, port, path, _ := parseServerAddr(serverAddr)
	wsURL := fmt.Sprintf("wss://%s:%s%s?token=%s", host, port, path, url.QueryEscape(token))
	
	requestHeader := http.Header{}
	requestHeader.Add("Host", host)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	
	dialer := websocket.Dialer{ 
		TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: host }, 
		HandshakeTimeout: 5 * time.Second,
	}
	
	if serverIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) { 
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(serverIP, p), 5*time.Second) 
		}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil { 
		if resp != nil { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }
		return nil, err 
	}
	return conn, nil
}

// [v12.1] 配置生成器：支持 Strategy 参数
// [v12.2 Fix] 修复多行输入导致解析失败的问题
func GenerateConfigJSON(serverAddr, serverIP, secretKey, socks5Addr, fallbackAddr, listenAddr, strategy string) string {
	token := secretKey
	if fallbackAddr != "" { token += "|" + fallbackAddr }

	// 1. 预处理：将所有换行符替换为分号，并将中文分号替换为英文分号
	normalizedAddr := strings.ReplaceAll(serverAddr, "\r\n", ";") // Windows 换行
	normalizedAddr = strings.ReplaceAll(normalizedAddr, "\n", ";")   // Linux 换行
	normalizedAddr = strings.ReplaceAll(normalizedAddr, "；", ";")    // 中文分号兼容

	var serverJSON string
	// 2. 检测是否包含分号（现在换行符也变成了分号）
	if strings.Contains(normalizedAddr, ";") {
		// 节点池模式
		rawPool := strings.Split(normalizedAddr, ";")
		var validPool []string
		
		// 3. 清洗数据：去除空行和空格
		for _, node := range rawPool {
			trimmed := strings.TrimSpace(node)
			if trimmed != "" {
				validPool = append(validPool, trimmed)
			}
		}

		// 兜底：如果清洗后只剩一个（或者空），回退到单节点逻辑
		if len(validPool) == 0 {
			serverJSON = fmt.Sprintf(`"server": ""`) // 空配置
		} else if len(validPool) == 1 {
			serverJSON = fmt.Sprintf(`"server": "%s"`, validPool[0])
		} else {
			poolJSON, _ := json.Marshal(validPool)
			// 注入 Strategy 字段
			serverJSON = fmt.Sprintf(`"server": "%s", "server_pool": %s, "strategy": "%s"`, validPool[0], string(poolJSON), strategy)
		}
	} else {
		// 单节点模式
		serverJSON = fmt.Sprintf(`"server": "%s"`, strings.TrimSpace(serverAddr))
	}

	config := fmt.Sprintf(`{
		"inbounds": [{"tag": "socks-in", "listen": "%s", "protocol": "socks"}],
		"outbounds": [{
			"tag": "proxy",
			"protocol": "ech-proxy",
			"settings": {
				%s,
				"server_ip": "%s",
				"token": "%s"`, listenAddr, serverJSON, serverIP, token)

	if socks5Addr != "" {
		config += fmt.Sprintf(`, "proxy_settings": {"socks5_address": "%s"}`, socks5Addr)
	}
	config += `}}], "routing": {"rules": [{"outboundTag": "proxy", "port": [0, 65535]}]}}`
	return config
}

// --- 辅助函数 (保持不变) ---
func pipeDirect(local net.Conn, ws *websocket.Conn) { 
	defer ws.Close(); defer local.Close()
	go func() { 
		for { 
			mt, r, err := ws.NextReader()
			if err != nil { break }
			if mt == websocket.BinaryMessage { if _, err := io.Copy(local, r); err != nil { break } }
		} 
		local.Close() 
	}() 
	bufPtr := bufPool.Get().([]byte); defer bufPool.Put(bufPtr)
	for { 
		n, err := local.Read(bufPtr)
		if n > 0 { if err := ws.WriteMessage(websocket.BinaryMessage, bufPtr[:n]); err != nil { break } } 
		if err != nil { break }
	} 
}
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	hostBytes := []byte(host); s5Bytes := []byte(s5); fbBytes := []byte(fb)
	if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 { return errors.New("address length exceeds 255 bytes") }
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hostBytes))); buf.Write(hostBytes)
	portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, port); buf.Write(portBytes)
	buf.WriteByte(byte(len(s5Bytes))); if len(s5Bytes) > 0 { buf.Write(s5Bytes) }
	buf.WriteByte(byte(len(fbBytes))); if len(fbBytes) > 0 { buf.Write(fbBytes) }
	if len(payload) > 0 { buf.Write(payload) }
	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
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
	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil 
}
func parseServerAddr(addr string) (host, port, path string, err error) { 
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }
	host, port, err = net.SplitHostPort(addr)
	if err != nil { host = addr; port = "443"; err = nil }
	return 
}
