// core/core-binary.go (v14.2 - Zeus Perfect Edition)
// [升级] 权重生效：实现 Weighted Hash 算法，支持 |weight 精确流量配比
// [升级] 端口解耦：分离 SNI 端口与 TCP 连接端口，实现极致伪装
// [状态] 逻辑完美闭环，无省略完整版

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"crypto/md5"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var globalRRIndex uint64

// [v14] 真实后端结构
type Backend struct {
	IP     string
	Port   string
	Weight int
}

// [v14] Node 结构
type Node struct {
	Domain   string    
	Backends []Backend 
}

type ProxySettings struct { 
	Server     string `json:"server"`      
	ServerIP   string `json:"server_ip"`   
	Token      string `json:"token"`
	Strategy   string `json:"strategy"`
	Rules      string `json:"rules"`
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
	NodePool   []Node `json:"-"` 
}

type Rule struct { Keyword string; Node Node }
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }

var ( 
	globalConfig Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule
)

var bufPool = sync.Pool{ New: func() interface{} { return make([]byte, 32*1024) } }

// 解析节点字符串 (支持权重 |n)
func parseNode(nodeStr string) Node {
	var n Node
	parts := strings.SplitN(nodeStr, "#", 2)
	n.Domain = strings.TrimSpace(parts[0])

	if len(parts) != 2 || parts[1] == "" {
		return n 
	}

	backendPart := strings.TrimSpace(parts[1])
	entries := strings.Split(backendPart, ",") 

	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" { continue }

		weight := 1 
		addr := e
		
		if strings.Contains(e, "|") {
			p := strings.SplitN(e, "|", 2)
			addr = p[0]
			w, err := strconv.Atoi(p[1])
			if err == nil && w > 0 {
				weight = w
			}
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = "" 
		}

		n.Backends = append(n.Backends, Backend{IP: host, Port: port, Weight: weight})
	}
	return n
}

// 规则解析器
func parseRules(pool []Node) {
	if len(globalConfig.Outbounds) == 0 { return }
	var s ProxySettings
	if err := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err != nil { return }
	if s.Rules == "" { return }

	rawRules := strings.ReplaceAll(s.Rules, "|", "\n")
	lines := strings.Split(rawRules, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }
		
		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			keyword := strings.TrimSpace(parts[0])
			nodeStr := strings.TrimSpace(parts[1])
			
			var foundNode Node
			aliasFound := false
			// 优先匹配节点池中的别名
			for _, pNode := range pool {
				if pNode.Domain == nodeStr {
					foundNode = pNode
					aliasFound = true
					break
				}
			}
			// 未找到别名，则按 Ares 格式解析
			if !aliasFound {
				foundNode = parseNode(nodeStr)
			}
			
			if keyword != "" && foundNode.Domain != "" {
				routingMap = append(routingMap, Rule{Keyword: keyword, Node: foundNode})
			}
		}
	}
}

// Outbound 解析器
func parseOutbounds() {
	for i, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				// 暴力清洗分隔符
				rawPool := strings.ReplaceAll(settings.Server, "\r\n", ";")
				rawPool = strings.ReplaceAll(rawPool, "\n", ";")
				rawPool = strings.ReplaceAll(rawPool, "，", ";")
				rawPool = strings.ReplaceAll(rawPool, ",", ";")
				rawPool = strings.ReplaceAll(rawPool, "；", ";")

				nodeStrs := strings.Split(rawPool, ";")
				
				for _, nodeStr := range nodeStrs {
					trimmed := strings.TrimSpace(nodeStr)
					if trimmed != "" {
						settings.NodePool = append(settings.NodePool, parseNode(trimmed))
					}
				}
				proxySettingsMap[outbound.Tag] = settings
				
				// 回写配置
				b, _ := json.Marshal(settings)
				globalConfig.Outbounds[i].Settings = b
			}
		}
	}
}

func StartInstance(configContent []byte) (net.Listener, error) {
	rand.Seed(time.Now().UnixNano())
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap = nil 
	
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	
	parseOutbounds()
	if s, ok := proxySettingsMap["proxy"]; ok {
		parseRules(s.NodePool) 
	}
	
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	
	mode := "Single Node"
	if s, ok := proxySettingsMap["proxy"]; ok {
		if len(s.NodePool) > 1 {
			mode = fmt.Sprintf("Zeus Pool (%d nodes, Strategy: %s)", len(s.NodePool), s.Strategy)
		} else if len(s.NodePool) == 1 {
			mode = fmt.Sprintf("Zeus Single (%s)", s.NodePool[0].Domain)
		}
		if len(routingMap) > 0 {
			mode += fmt.Sprintf(" + %d Rules", len(routingMap))
		}
	}
	log.Printf("[Core] Xlink Zeus Engine (v14.1 Perfect) Listening on %s [%s]", inbound.Listen, mode)
	
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { break }
			go handleGeneralConnection(conn, inbound.Tag)
		}
	}()
	return listener, nil
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
	case 0x05: target, err = handleSOCKS5(conn, inboundTag); mode = 1
	default: target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil { return }

	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil { 
		log.Printf("[Core] Error connecting to %s: %v", target, err)
		return 
	}
	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	pipeDirect(conn, wsConn)
}

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 { fallback = parts[1] }
	socks5 := ""
	if settings.ForwarderSettings != nil { socks5 = settings.ForwarderSettings.Socks5Address }

	var targetNode Node
	logMsg := ""

	// 1. [外层调度] 规则匹配
	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetNode = rule.Node
			logMsg = fmt.Sprintf("[Core] Rule Hit -> %s | SNI: %s (Rule: %s)", target, targetNode.Domain, rule.Keyword)
			break
		}
	}

	// 2. [外层调度] 负载均衡
	if targetNode.Domain == "" {
		if len(settings.NodePool) > 0 {
			poolLen := uint64(len(settings.NodePool))
			strategy := settings.Strategy
			switch strategy {
			case "rr":
				idx := atomic.AddUint64(&globalRRIndex, 1)
				targetNode = settings.NodePool[idx%poolLen]
			case "hash":
				h := md5.Sum([]byte(target))
				hashVal := binary.BigEndian.Uint64(h[:8])
				targetNode = settings.NodePool[hashVal%poolLen]
			default:
				targetNode = settings.NodePool[rand.Intn(int(poolLen))]
			}
			logMsg = fmt.Sprintf("[Core] LB -> %s | SNI: %s | Algo: %s", target, targetNode.Domain, strategy)
		} else {
			return nil, errors.New("no nodes configured in pool")
		}
	}
	
	log.Print(logMsg)

	// 3. [内层调度] 选择真实后端 (支持权重)
	backend := selectBackend(targetNode.Backends, target)
	if backend.IP == "" {
		backend.IP = settings.ServerIP // 兜底使用全局 IP
	}

	if backend.IP != "" {
		// Log 显示真实出口 (IP:Port)
		log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real)", targetNode.Domain, backend.IP, backend.Port)
	}

	// 4. 发起连接 (解耦 SNI 和 TCP 端口)
	wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
	if err != nil { return nil, err }

	err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
	if err != nil { wsConn.Close(); return nil, err }
	return wsConn, nil
}

// [v14.1 核心修复] 加权哈希选择器
func selectBackend(backends []Backend, key string) Backend {
	if len(backends) == 0 { return Backend{} }
	if len(backends) == 1 { return backends[0] }

	// 1. 计算总权重
	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.Weight
	}

	// 2. 计算目标哈希值，映射到 [0, totalWeight) 区间
	h := md5.Sum([]byte(key))
	hashVal := binary.BigEndian.Uint64(h[:8])
	
	// 防止 mod 0 panic (防御性编程)
	if totalWeight == 0 {
		targetVal := int(hashVal % uint64(len(backends)))
		return backends[targetVal]
	}
	
	targetVal := int(hashVal % uint64(totalWeight))

	// 3. 权重区间查找
	currentWeight := 0
	for _, b := range backends {
		currentWeight += b.Weight
		if targetVal < currentWeight {
			return b
		}
	}
	return backends[0] // Fallback
}

// [v14.1 核心修复] 端口解耦拨号器
func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) {
	// 1. 解析 SNI 域名中的端口 (用于伪装和 WS 握手)
	sniHost, sniPort, err := net.SplitHostPort(sni)
	if err != nil {
		sniHost = sni
		sniPort = "443"
	}

	// 2. 确定真实的 TCP 连接端口
	dialPort := sniPort // 默认与 SNI 端口一致
	if backend.Port != "" {
		dialPort = backend.Port // 如果后端指定了端口，强制使用后端端口
	}

	// 3. 构造 WebSocket URL (始终使用 SNI 信息，保证 Host 头正确)
	wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token))
	
	requestHeader := http.Header{}
	requestHeader.Add("Host", sniHost)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	
	dialer := websocket.Dialer{ 
		TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, 
		HandshakeTimeout: 5 * time.Second,
	}
	
	// 4. 强制 TCP 连接到真实后端 IP 和 端口
	if backend.IP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) { 
			// 忽略 addr 中的域名解析，直接连 IP:DialPort
			return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) 
		}
	}

	return dialer.Dial(wsURL, requestHeader)
}

func GenerateConfigJSON(serverAddr, serverIP, secretKey, socks5Addr, fallbackAddr, listenAddr, strategy, rules string) string {
	token := secretKey
	if fallbackAddr != "" { token += "|" + fallbackAddr }
	serverJSON, _ := json.Marshal(serverAddr)
	rulesJSON, _ := json.Marshal(rules)
	config := fmt.Sprintf(`{
		"inbounds": [{"tag": "socks-in", "listen": "%s", "protocol": "socks"}],
		"outbounds": [{
			"tag": "proxy",
			"protocol": "ech-proxy",
			"settings": {
				"server": %s,
				"server_ip": "%s",
				"token": "%s",
				"strategy": "%s",
				"rules": %s`, listenAddr, string(serverJSON), serverIP, token, strategy, string(rulesJSON))
	if socks5Addr != "" { config += fmt.Sprintf(`, "proxy_settings": {"socks5_address": "%s"}`, socks5Addr) }
	config += `}}], "routing": {}}` 
	return config
}

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
