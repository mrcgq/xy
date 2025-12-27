// core/core-binary.go (v18.1 - Genesis Stable)
// [修复] 修复 pingNode 调用参数过多的错误
// [修复] 修复 connectNanoTunnel 未使用 secretKey 的错误
// [架构] 完美集成 v18 测速 + v14.1 核心

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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var globalRRIndex uint64

// --- 结构定义 ---
type Backend struct { IP string; Port string; Weight int }
type Node struct { Domain string; Backends []Backend }
type Rule struct { Keyword string; Node Node; Strategy string } 

type ProxySettings struct { 
	Server     string `json:"server"`      
	ServerIP   string `json:"server_ip"`   
	Token      string `json:"token"`
	Strategy   string `json:"strategy"`
	Rules      string `json:"rules"`
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
	NodePool   []Node `json:"-"` 
}

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

// ======================== [v18] 测速模式核心 ========================

type TestResult struct {
	Node   Node
	Delay  time.Duration
	Error  error
}

// pingNode [修复版]
func pingNode(node Node, token string, globalIP string, results chan<- TestResult) {
	startTime := time.Now()
	
	// 1. 预处理后端：从池中选一个，并应用全局 IP 兜底
	backend := selectBackend(node.Backends, "")
	if backend.IP == "" {
		backend.IP = globalIP
	}

	// 2. 发起连接 (修复：只传 3 个参数)
	conn, err := dialZeusWebSocket(node.Domain, backend, token)
	
	if err != nil {
		results <- TestResult{Node: node, Error: err}
		return
	}
	conn.Close() 
	
	delay := time.Since(startTime)
	results <- TestResult{Node: node, Delay: delay}
}

// RunSpeedTest
func RunSpeedTest(serverAddr, token, globalIP string) {
	// 1. 解析节点池
	// 清洗换行符，兼容 C 客户端传来的格式
	rawPool := strings.ReplaceAll(serverAddr, "\r\n", ";")
	rawPool = strings.ReplaceAll(rawPool, "\n", ";")
	nodeStrs := strings.Split(rawPool, ";")
	
	var nodes []Node
	for _, nodeStr := range nodeStrs {
		trimmed := strings.TrimSpace(nodeStr)
		if trimmed != "" {
			nodes = append(nodes, parseNode(trimmed))
		}
	}

	if len(nodes) == 0 {
		log.Println("No valid nodes found in server pool.")
		return
	}

	// 2. 并发测速
	var wg sync.WaitGroup
	results := make(chan TestResult, len(nodes))
	
	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			// 注意：Token 需要处理，如果在测速模式下 token 包含 |fallback，需要切割
			// 但通常测速只测连通性，用原始 token 握手即可
			parts := strings.SplitN(token, "|", 2)
			realKey := parts[0]
			pingNode(n, realKey, globalIP, results)
		}(node)
	}

	wg.Wait()
	close(results)

	// 3. 收集并排序结果
	var successful []TestResult
	var failed []TestResult

	for res := range results {
		if res.Error == nil {
			successful = append(successful, res)
		} else {
			failed = append(failed, res)
		}
	}
	
	sort.Slice(successful, func(i, j int) bool {
		return successful[i].Delay < successful[j].Delay
	})
	
	// 4. 打印报告
	fmt.Println("\nPing Test Report") // 这里的关键词会被 C 客户端捕获翻译
	fmt.Println("\nSuccessful Nodes")
	for i, res := range successful {
		fmt.Printf("%d. %-40s | Delay: %v\n", i+1, formatNode(res.Node), res.Delay.Round(time.Millisecond))
	}

	if len(failed) > 0 {
		fmt.Println("\nFailed Nodes")
		for _, res := range failed {
			fmt.Printf("- %-40s | Error: %v\n", formatNode(res.Node), res.Error)
		}
	}
	fmt.Println("\n------------------------------------")
}

func formatNode(n Node) string {
    res := n.Domain
    if len(n.Backends) > 0 {
        res += "#"
        var backends []string
        for _, b := range n.Backends {
            bStr := b.IP
            if b.Port != "" { bStr += ":" + b.Port }
            if b.Weight > 1 { bStr += "|" + strconv.Itoa(b.Weight) }
            backends = append(backends, bStr)
        }
        res += strings.Join(backends, ",")
    }
    return res
}


// ======================== 代理模式核心 (v16/v14 逻辑) ========================

func parseNode(nodeStr string) Node {
	var n Node
	parts := strings.SplitN(nodeStr, "#", 2)
	n.Domain = strings.TrimSpace(parts[0])
	if len(parts) != 2 || parts[1] == "" { return n }
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
			if w, err := strconv.Atoi(p[1]); err == nil && w > 0 { weight = w }
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil { host = addr; port = "" }
		n.Backends = append(n.Backends, Backend{IP: host, Port: port, Weight: weight})
	}
	return n
}

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
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			keyword := strings.TrimSpace(parts[0])
			nodeStr := strings.TrimSpace(parts[1])
			strategy := ""
			if len(parts) >= 3 { strategy = strings.TrimSpace(parts[2]) }
			var foundNode Node
			aliasFound := false
			for _, pNode := range pool {
				if pNode.Domain == nodeStr {
					foundNode = pNode
					aliasFound = true
					break
				}
			}
			if !aliasFound { foundNode = parseNode(nodeStr) }
			if keyword != "" && foundNode.Domain != "" {
				routingMap = append(routingMap, Rule{Keyword: keyword, Node: foundNode, Strategy: strategy})
			}
		}
	}
}

func parseOutbounds() {
	for i, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				rawPool := strings.ReplaceAll(settings.Server, "\r\n", ";")
				rawPool = strings.ReplaceAll(rawPool, "\n", ";")
				nodeStrs := strings.Split(rawPool, ";")
				for _, nodeStr := range nodeStrs {
					trimmed := strings.TrimSpace(nodeStr)
					if trimmed != "" {
						settings.NodePool = append(settings.NodePool, parseNode(trimmed))
					}
				}
				proxySettingsMap[outbound.Tag] = settings
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
	if s, ok := proxySettingsMap["proxy"]; ok { parseRules(s.NodePool) }
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
		if len(routingMap) > 0 { mode += fmt.Sprintf(" + %d Rules", len(routingMap)) }
	}
	log.Printf("[Core] Xlink Zeus Engine (v18.1 Final) Listening on %s [%s]", inbound.Listen, mode)
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
		// log.Printf("[Core] Error connecting to %s: %v", target, err)
		return 
	}
	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	pipeDirect(conn, wsConn)
}

// [核心] 调度与连接 (修复了 secretKey 未使用的问题)
func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	// [Fix] 解析 Token，提取纯密钥
	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	
	fallback := ""; if len(parts) > 1 { fallback = parts[1] }
	socks5 := ""; if settings.ForwarderSettings != nil { socks5 = settings.ForwarderSettings.Socks5Address }

	// --- 内部重试函数 ---
	tryConnectOnce := func() (*websocket.Conn, error) {
		var targetNode Node
		var logMsg string
		var finalStrategy string

		// 1. 规则匹配
		ruleHit := false
		for _, rule := range routingMap {
			if strings.Contains(target, rule.Keyword) {
				targetNode = rule.Node
				finalStrategy = rule.Strategy
				if finalStrategy == "" { finalStrategy = settings.Strategy }
				logMsg = fmt.Sprintf("[Core] Rule Hit -> %s | SNI: %s (Rule: %s, Algo: %s)", target, targetNode.Domain, rule.Keyword, finalStrategy)
				ruleHit = true
				break
			}
		}

		// 2. 负载均衡
		if !ruleHit {
			if len(settings.NodePool) > 0 {
				finalStrategy = settings.Strategy
				switch finalStrategy {
				case "rr":
					idx := atomic.AddUint64(&globalRRIndex, 1)
					targetNode = settings.NodePool[idx%uint64(len(settings.NodePool))]
				case "hash":
					h := md5.Sum([]byte(target))
					hashVal := binary.BigEndian.Uint64(h[:8])
					targetNode = settings.NodePool[hashVal%uint64(len(settings.NodePool))]
				default:
					targetNode = settings.NodePool[rand.Intn(len(settings.NodePool))]
				}
				logMsg = fmt.Sprintf("[Core] LB -> %s | SNI: %s | Algo: %s", target, targetNode.Domain, finalStrategy)
			} else {
				return nil, errors.New("no nodes configured in pool")
			}
		}

		log.Print(logMsg)

		// 3. 内层调度
		backend := selectBackend(targetNode.Backends, target)
		if backend.IP == "" { backend.IP = settings.ServerIP }
		if backend.IP != "" { log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real)", targetNode.Domain, backend.IP, backend.Port) }
		
		// 4. 拨号 [Fix: 使用 secretKey]
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
		if err != nil { return nil, err }
		
		// 5. 发送协议头
		err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
		if err != nil { wsConn.Close(); return nil, err }
		return wsConn, nil
	}
	
	// --- 执行连接与故障转移 ---
	conn, err := tryConnectOnce()
	
	if err != nil && len(settings.NodePool) > 1 {
		log.Printf("[Core] Connect failed: %v. Activating Passive Failover...", err)
		return tryConnectOnce() 
	}

	return conn, err
}

func selectBackend(backends []Backend, key string) Backend {
	if len(backends) == 0 { return Backend{} }
	if len(backends) == 1 { return backends[0] }
	totalWeight := 0
	for _, b := range backends { totalWeight += b.Weight }
	if totalWeight == 0 { return backends[rand.Intn(len(backends))] }
	h := md5.Sum([]byte(key))
	hashVal := binary.BigEndian.Uint64(h[:8])
	targetVal := int(hashVal % uint64(totalWeight))
	currentWeight := 0
	for _, b := range backends {
		currentWeight += b.Weight
		if targetVal < currentWeight { return b }
	}
	return backends[0] 
}

func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) {
	sniHost, sniPort, err := net.SplitHostPort(sni)
	if err != nil { sniHost = sni; sniPort = "443" }
	dialPort := sniPort
	if backend.Port != "" { dialPort = backend.Port }
	wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token))
	requestHeader := http.Header{}
	requestHeader.Add("Host", sniHost)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	dialer := websocket.Dialer{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, HandshakeTimeout: 5 * time.Second }
	if backend.IP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) { 
			return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) 
		}
	}
	
	// [Fix] 显式接收 3 个返回值
	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("handshake failed with status %d", resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
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
			"settings": { "server": %s, "server_ip": "%s", "token": "%s", "strategy": "%s", "rules": %s`,
			listenAddr, string(serverJSON), serverIP, token, strategy, string(rulesJSON))
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
