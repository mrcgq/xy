// core/core-binary.go (v19.0 - Observer Edition)
// [新增] 握手延迟记录 (Latency Tracking)
// [新增] 流量统计与连接时长记录 (Traffic Auditing)
// [架构] 集成 v18 测速 + v16 策略 + v15 容灾 + v14 双层池
// [状态] 完整无省略版

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
type Backend struct {
	IP     string
	Port   string
	Weight int
}

type Node struct {
	Domain   string    
	Backends []Backend 
}

type Rule struct { 
	Keyword  string
	Node     Node
	Strategy string 
}

type ProxySettings struct { 
	Server     string   `json:"server"`      
	ServerIP   string   `json:"server_ip"`   
	Token      string   `json:"token"`
	Strategy   string   `json:"strategy"`
	Rules      string   `json:"rules"`
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

// ======================== 节点与规则解析 ========================

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
			if w, err := strconv.Atoi(p[1]); err == nil && w > 0 {
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
			if len(parts) >= 3 {
				strategy = strings.TrimSpace(parts[2])
			}
			
			var foundNode Node
			aliasFound := false
			for _, pNode := range pool {
				if pNode.Domain == nodeStr {
					foundNode = pNode
					aliasFound = true
					break
				}
			}
			if !aliasFound {
				foundNode = parseNode(nodeStr)
			}
			
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
				b, _ := json.Marshal(settings)
				globalConfig.Outbounds[i].Settings = b
			}
		}
	}
}

// ======================== 测速模块 (v18 Integrated) ========================

type TestResult struct {
	Node   Node
	Delay  time.Duration
	Error  error
}

func pingNode(node Node, token string, globalIP string, results chan<- TestResult) {
	startTime := time.Now()
	
	backend := selectBackend(node.Backends, "")
	if backend.IP == "" {
		backend.IP = globalIP
	}

	conn, err := dialZeusWebSocket(node.Domain, backend, token)
	if err != nil {
		results <- TestResult{Node: node, Error: err}
		return
	}
	conn.Close() 
	
	delay := time.Since(startTime)
	results <- TestResult{Node: node, Delay: delay}
}

func RunSpeedTest(serverAddr, token, globalIP string) {
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

	var wg sync.WaitGroup
	results := make(chan TestResult, len(nodes))
	
	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			parts := strings.SplitN(token, "|", 2)
			pingNode(n, parts[0], globalIP, results)
		}(node)
	}

	wg.Wait()
	close(results)

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
	
	fmt.Println("\nPing Test Report")
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

// ======================== 主运行逻辑 ========================

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
	log.Printf("[Core] Xlink Observer Engine (v19.0) Listening on %s [%s]", inbound.Listen, mode)
	
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

	// 传入 target 以便 pipeDirect 打印日志
	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	
	if err != nil { 
		// 连接失败日志已在内部打印，此处略过
		return 
	}

	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	// [v19] 调用带统计的管道
	pipeDirect(conn, wsConn, target)
}

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

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

		// [v19] 计时开始
		start := time.Now()

		// 4. 拨号
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
		
		// [v19] 计算延迟
		latency := time.Since(start).Milliseconds()

		if err != nil { return nil, err }

		if backend.IP != "" {
			// [v19] 日志包含 Latency
			log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real) | Latency: %dms", targetNode.Domain, backend.IP, backend.Port, latency)
		}

		err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
		if err != nil { wsConn.Close(); return nil, err }
		return wsConn, nil
	}
	
	// [v15] 被动故障转移
	conn, err := tryConnectOnce()
	if err != nil && len(settings.NodePool) > 1 {
		log.Printf("[Core] Connect failed: %v. Retry...", err)
		return tryConnectOnce() 
	}

	return conn, err
}

func selectBackend(backends []Backend, key string) Backend {
	if len(backends) == 0 { return Backend{} }
	if len(backends) == 1 { return backends[0] }

	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.Weight
	}

	h := md5.Sum([]byte(key))
	hashVal := binary.BigEndian.Uint64(h[:8])
	
	if totalWeight == 0 {
		targetVal := int(hashVal % uint64(len(backends)))
		return backends[targetVal]
	}
	
	targetVal := int(hashVal % uint64(totalWeight))

	currentWeight := 0
	for _, b := range backends {
		currentWeight += b.Weight
		if targetVal < currentWeight {
			return b
		}
	}
	return backends[0] 
}

func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) {
	sniHost, sniPort, err := net.SplitHostPort(sni)
	if err != nil {
		sniHost = sni
		sniPort = "443"
	}
	dialPort := sniPort
	if backend.Port != "" {
		dialPort = backend.Port
	}

	wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token))
	
	requestHeader := http.Header{}
	requestHeader.Add("Host", sniHost)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	
	dialer := websocket.Dialer{ 
		TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, 
		HandshakeTimeout: 5 * time.Second,
	}
	
	if backend.IP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) { 
			return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) 
		}
	}

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
			"settings": {
				"server": %s,
				"server_ip": "%s",
				"token": "%s",
				"strategy": "%s",
				"rules": %s`, listenAddr, string(serverJSON), serverIP, token, strategy, string(rulesJSON))

	if socks5Addr != "" {
		config += fmt.Sprintf(`, "proxy_settings": {"socks5_address": "%s"}`, socks5Addr)
	}
	config += `}}], "routing": {}}` 
	return config
}

// [v19] 升级版管道：支持流量统计
func pipeDirect(local net.Conn, ws *websocket.Conn, target string) { 
	defer ws.Close()
	defer local.Close()

	var upBytes, downBytes int64
	startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	// Downlink: WS -> TCP
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		
		for {
			mt, r, err := ws.NextReader()
			if err != nil { break }
			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				if err == nil { atomic.AddInt64(&downBytes, n) }
				if err != nil { break }
			}
		}
		local.Close() 
	}() 

	// Uplink: TCP -> WS
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		for {
			n, err := local.Read(buf)
			if n > 0 {
				atomic.AddInt64(&upBytes, int64(n))
				err := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				if err != nil { break }
			}
			if err != nil { break }
		}
	}()

	wg.Wait()
	duration := time.Since(startTime)
	
	// [v19] 打印统计日志
	log.Printf("[Stats] %s | Up: %s | Down: %s | Time: %v", 
		target, formatBytes(upBytes), formatBytes(downBytes), duration.Round(time.Second))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ... (sendNanoHeaderV2, handleSOCKS5, handleHTTP, parseServerAddr 保持 v14.1 不变)
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
