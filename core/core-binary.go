// core/core-binary.go (v28.0 - Self-Adaptive Edition)
// [版本] v28.0 自适应版
// [新特性1] 主动健康探测：后台每分钟 Ping 全体节点，实时掌握线路质量
// [新特性2] 智能负载均衡：优先选择延迟最低的节点，不再随机
// [新特性3] 重连熔断器：防止极端网络下因疯狂重连导致崩溃
// [状态] Xlink 最终形态，拥有自我调节能力的智能内核

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
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

// ================== [v28.0] 智能配置 ==================

const (
	MODE_AUTO = 0 
	MODE_KEEP = 1 
	MODE_CUT  = 2 
)

// 动态阈值 (8MB ~ 12MB)
func getDynamicThreshold() int64 {
	base := int64(8 * 1024 * 1024)
	jitter := rand.Int63n(4 * 1024 * 1024)
	return base + jitter
}

// 豁免名单
var disconnectExemptList = []string{
	"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
	"nflxvideo.net", "vimeo.com", "live", "stream", "twitch.tv",
	"telesco.pe", "tdesktop.com", "web.whatsapp.com", "discord.com",
	"aistudio.google.com", "gemini.google.com", "bard.google.com",
	"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
	"anthropic.com", "claude.ai",
	"googleapis.com", "gstatic.com", 
	"figma.com", "slack.com", "notion.so",
}

var disconnectSuffixRegex = regexp.MustCompile(`(?i)\.(m3u8|mp4|flv|mkv|avi|mov|ts|webm)$`)

func shouldDisableDisconnect(target string) bool {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil { host = target }
	host = strings.ToLower(host)
	
	for _, keyword := range disconnectExemptList {
		if strings.Contains(host, keyword) { return true }
	}
	if disconnectSuffixRegex.MatchString(host) { return true }
	if portStr != "80" && portStr != "443" && portStr != "" { return true }
	
	return false
}

// ============================================================

var globalRRIndex uint64

type Backend struct { IP, Port string; Weight int }
type Node struct {
	Domain   string
	Backends []Backend
	// [v28.0] 新增：节点的健康状态
	mu      sync.RWMutex
	latency time.Duration
	alive   bool
}

const (
	MatchTypeSubstring = iota
	MatchTypeDomain
	MatchTypeRegex
	MatchTypeGeosite
	MatchTypeGeoIP
)

type Rule struct {
	Type           int
	Value          string
	CompiledRegex  *regexp.Regexp
	Node           *Node // [v28.0] 改为指针，以便共享健康状态
	Strategy       string
	DisconnectMode int
}

type ProxySettings struct {
	Server            string                  `json:"server"`
	ServerIP          string                  `json:"server_ip"`
	Token             string                  `json:"token"`
	Strategy          string                  `json:"strategy"`
	Rules             string                  `json:"rules"`
	GlobalKeepAlive   bool                    `json:"global_keep_alive"` 
	S5                string                  `json:"s5,omitempty"` 
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
	NodePool          []*Node                 `json:"-"` // [v28.0] 改为指针切片
}

// ... (Config, Inbound, Outbound, ProxyForwarderSettings struct unchanged)
type Config struct{ Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"` }
type Inbound struct{ Tag, Listen, Protocol string }
type Outbound struct { Tag, Protocol string; Settings json.RawMessage }
type ProxyForwarderSettings struct{ Socks5Address string }

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule
	geositeMatcher   map[string][]*routercommon.Domain
	geodataMutex     sync.RWMutex
)

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

// ======================== 主入口 ========================

func main() {
	configPath := flag.String("c", "", "Path to config file (JSON)")
	ping := flag.Bool("ping", false, "Ping mode")
	server := flag.String("server", "", "Server address (pool) for ping")
	key := flag.String("key", "", "Secret key for ping")
	serverIP := flag.String("ip", "", "Global fallback server IP for ping")

	flag.Parse()
	rand.Seed(time.Now().UnixNano())

	if *ping {
		if *server == "" || *key == "" {
			log.Fatal("Ping mode requires -server and -key")
		}
		// RunSpeedTest needs to be adapted for *Node
		// For simplicity, we create temporary Node objects for pinging
		tempNodes := parseNodesForPing(*server)
		RunSpeedTest(tempNodes, *key, *serverIP)
		return
	}

	if *configPath == "" {
		log.Fatal("Config file path is required. Usage: -c config.json")
	}

	configBytes, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	listener, err := StartInstance(configBytes)
	if err != nil {
		log.Fatalf("Failed to start instance: %v", err)
	}
	
	select {} 
	_ = listener
}

// ======================== 核心逻辑 ========================

// ... (checkFileDependency, loadGeodata, matchDomainRule are unchanged)
func checkFileDependency(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) { return false }
	return !info.IsDir()
}

func loadGeodata() {
	rawBytes, err := os.ReadFile("geosite.dat")
	if err != nil { return }
	var geositeList routercommon.GeoSiteList
	if err := proto.Unmarshal(rawBytes, &geositeList); err != nil {
		log.Printf("[Core] [依赖检查] 错误: 解析 geosite.dat 失败! %v", err)
		return
	}
	geodataMutex.Lock()
	defer geodataMutex.Unlock()
	matcher := make(map[string][]*routercommon.Domain)
	for _, site := range geositeList.Entry {
		matcher[strings.ToLower(site.CountryCode)] = site.Domain
	}
	geositeMatcher = matcher
}

func matchDomainRule(domain string, rule *routercommon.Domain) bool {
	switch rule.Type {
	case routercommon.Domain_Plain: return strings.Contains(domain, rule.Value)
	case routercommon.Domain_Regex: matched, _ := regexp.MatchString(rule.Value, domain); return matched
	case routercommon.Domain_RootDomain: return domain == rule.Value || strings.HasSuffix(domain, "."+rule.Value)
	case routercommon.Domain_Full: return domain == rule.Value
	default: return false
	}
}

func isDomainInGeosite(domain, geositeCategory string) bool {
	geodataMutex.RLock()
	defer geodataMutex.RUnlock()
	if geositeMatcher == nil { return false }
	matchers, found := geositeMatcher[strings.ToLower(geositeCategory)]
	if !found { return false }
	for _, matcher := range matchers {
		if matchDomainRule(domain, matcher) { return true }
	}
	return false
}

// [v28.0] parseNode now returns a pointer to Node
func parseNode(nodeStr string) *Node {
	n := &Node{alive: true, latency: time.Hour} // Default to alive with high latency
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
		if err != nil { host, port = addr, "" }
		n.Backends = append(n.Backends, Backend{IP: host, Port: port, Weight: weight})
	}
	return n
}

// [v28.0] parseRules adapted for *Node
func parseRules(pool []*Node) {
	if len(globalConfig.Outbounds) == 0 { return }
	var s ProxySettings
	if err := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err != nil { return }
	if s.Rules == "" { return }

	rawRules := strings.ReplaceAll(s.Rules, "\r", "")
	lines := strings.Split(rawRules, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			keyword := strings.TrimSpace(parts[0])
			rightSide := strings.TrimSpace(parts[1])
			strategy := ""
			if len(parts) >= 3 { strategy = strings.TrimSpace(parts[2]) }
			disconnectMode := MODE_AUTO
			if strings.HasSuffix(rightSide, "|keep") {
				disconnectMode = MODE_KEEP
				rightSide = strings.TrimSuffix(rightSide, "|keep")
			} else if strings.HasSuffix(rightSide, "|cut") {
				disconnectMode = MODE_CUT
				rightSide = strings.TrimSuffix(rightSide, "|cut")
			}
			var ruleType int
			var ruleValue string
			var compiledRegex *regexp.Regexp
			
			if strings.HasPrefix(keyword, "regexp:") {
				ruleType, ruleValue = MatchTypeRegex, strings.TrimPrefix(keyword, "regexp:")
				compiledRegex = regexp.MustCompile(ruleValue)
			} else if strings.HasPrefix(keyword, "domain:") {
				ruleType, ruleValue = MatchTypeDomain, strings.TrimPrefix(keyword, "domain:")
			} else if strings.HasPrefix(keyword, "geosite:") {
				ruleType, ruleValue = MatchTypeGeosite, strings.TrimPrefix(keyword, "geosite:")
			} else if strings.HasPrefix(keyword, "geoip:") {
				ruleType, ruleValue = MatchTypeGeoIP, strings.TrimPrefix(keyword, "geoip:")
			} else {
				ruleType, ruleValue = MatchTypeSubstring, keyword
			}

			var foundNode *Node
			aliasFound := false
			for _, pNode := range pool {
				if pNode.Domain == rightSide {
					foundNode = pNode
					aliasFound = true
					break
				}
			}
			if !aliasFound { foundNode = parseNode(rightSide) }
			if keyword != "" {
				routingMap = append(routingMap, Rule{
					Type:           ruleType,
					Value:          ruleValue,
					CompiledRegex:  compiledRegex,
					Node:           foundNode,
					Strategy:       strategy,
					DisconnectMode: disconnectMode,
				})
			}
		}
	}
}

// [v28.0] parseOutbounds adapted for *Node
func parseOutbounds() {
	for i, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				rawPool := strings.ReplaceAll(settings.Server, "\r\n", ";"); rawPool = strings.ReplaceAll(rawPool, "\n", ";"); rawPool = strings.ReplaceAll(rawPool, "，", ";"); rawPool = strings.ReplaceAll(rawPool, ",", ";"); rawPool = strings.ReplaceAll(rawPool, "；", ";")
				nodeStrs := strings.Split(rawPool, ";")
				for _, nodeStr := range nodeStrs { if trimmed := strings.TrimSpace(nodeStr); trimmed != "" { settings.NodePool = append(settings.NodePool, parseNode(trimmed)) } }
				proxySettingsMap[outbound.Tag] = settings; b, _ := json.Marshal(settings); globalConfig.Outbounds[i].Settings = b
			}
		}
	}
}

func StartInstance(configContent []byte) (net.Listener, error) {
	rand.Seed(time.Now().UnixNano()); proxySettingsMap = make(map[string]ProxySettings); routingMap = nil
	log.Println("[Core] [系统初始化] 正在加载 v28.0 (自适应版)...")
	if checkFileDependency("xray.exe") { log.Println("[Core] [依赖检查] ✅ xray.exe 匹配成功! [智能分流] 模式可用。") } else { log.Println("[Core] [依赖检查] ⚠️ xray.exe 未找到!") }
	if checkFileDependency("geosite.dat") { log.Println("[Core] [依赖检查] ✅ geosite.dat 匹配成功!"); loadGeodata() } else { log.Println("[Core] [依赖检查] ⚠️ geosite.dat 未找到!") }
	if checkFileDependency("geoip.dat") { log.Println("[Core] [依赖检查] ✅ geoip.dat 匹配成功!") } else { log.Println("[Core] [依赖检查] ⚠️ geoip.dat 未找到!") }
	log.Println("------------------------------------")
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds(); 
	if s, ok := proxySettingsMap["proxy"]; ok { 
		parseRules(s.NodePool)
		// [v28.0] 启动后台健康探测器
		go healthChecker(s.NodePool, s.Token, s.ServerIP)
	}
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]; listener, err := net.Listen("tcp", inbound.Listen); if err != nil { return nil, err }
	mode := "Single Node"; if s, ok := proxySettingsMap["proxy"]; ok { if len(s.NodePool) > 1 { mode = fmt.Sprintf("Zeus Pool (%d nodes)", len(s.NodePool)) } else if len(s.NodePool) == 1 { mode = fmt.Sprintf("Zeus Single") }; if len(routingMap) > 0 { mode += fmt.Sprintf(" + Rules") } }
	if s, ok := proxySettingsMap["proxy"]; ok && s.GlobalKeepAlive { log.Println("[Core] ★★★ 全局沉浸模式 (L3) 已开启 ★★★") }
	log.Printf("[Core] Xlink Engine v28 Listening on %s [%s]", inbound.Listen, mode)
	go func() { for { conn, err := listener.Accept(); if err != nil { break }; go handleGeneralConnection(conn, inbound.Tag) } }()
	return listener, nil
}

// ... (TestResult struct, pingNode, RunSpeedTest, formatNode are mostly unchanged but adapted for *Node)
type TestResult struct { Node *Node; Delay time.Duration; Error error }
func pingNode(node *Node, token, globalIP string, results chan<- TestResult) { startTime := time.Now(); backend := selectBackend(node.Backends, ""); if backend.IP == "" { backend.IP = globalIP }; conn, err := dialZeusWebSocket(node.Domain, backend, token); if err != nil { results <- TestResult{Node: node, Error: err}; return }; conn.Close(); delay := time.Since(startTime); results <- TestResult{Node: node, Delay: delay} }
func parseNodesForPing(serverAddr string) []*Node { var nodes []*Node; rawPool := strings.ReplaceAll(serverAddr, "\r\n", ";"); rawPool = strings.ReplaceAll(rawPool, "\n", ";"); nodeStrs := strings.Split(rawPool, ";"); for _, nodeStr := range nodeStrs { if trimmed := strings.TrimSpace(nodeStr); trimmed != "" { nodes = append(nodes, parseNode(trimmed)) } }; return nodes }
func RunSpeedTest(nodes []*Node, token, globalIP string) { if len(nodes) == 0 { log.Println("No valid nodes found."); return }; var wg sync.WaitGroup; results := make(chan TestResult, len(nodes)); for _, node := range nodes { wg.Add(1); go func(n *Node) { defer wg.Done(); parts := strings.SplitN(token, "|", 2); pingNode(n, parts[0], globalIP, results) }(node) }; wg.Wait(); close(results); var successful, failed []TestResult; for res := range results { if res.Error == nil { successful = append(successful, res) } else { failed = append(failed, res) } }; sort.Slice(successful, func(i, j int) bool { return successful[i].Delay < successful[j].Delay }); fmt.Println("\nPing Test Report"); for i, res := range successful { fmt.Printf("%d. %-40s | Delay: %v\n", i+1, formatNode(res.Node), res.Delay.Round(time.Millisecond)) }; if len(failed) > 0 { fmt.Println("\nFailed Nodes"); for _, res := range failed { fmt.Printf("- %-40s | Error: %v\n", formatNode(res.Node), res.Error) } }; fmt.Println("\n------------------------------------") }
func formatNode(n *Node) string { if n == nil { return "" }; res := n.Domain; if len(n.Backends) > 0 { res += "#..."; }; return res }

// [v28.0] 新增：后台健康探测器
func healthChecker(nodes []*Node, token, globalIP string) {
	if len(nodes) <= 1 { return } // 单节点无需探测
	log.Println("[Core] [自适应] 后台健康探测器已启动...")
	parts := strings.SplitN(token, "|", 2)
	pingToken := parts[0]
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		var wg sync.WaitGroup
		for _, node := range nodes {
			wg.Add(1)
			go func(n *Node) {
				defer wg.Done()
				start := time.Now()
				// 使用简化的 ping 逻辑，不创建 channel
				backend := selectBackend(n.Backends, "")
				if backend.IP == "" { backend.IP = globalIP }
				
				conn, err := dialZeusWebSocket(n.Domain, backend, pingToken)
				
				n.mu.Lock()
				if err != nil {
					n.alive = false
					n.latency = time.Hour // 惩罚性高延迟
					// log.Printf("[Core] [健康探测] 节点 %s 异常: %v", n.Domain, err)
				} else {
					conn.Close()
					n.alive = true
					n.latency = time.Since(start)
					// log.Printf("[Core] [健康探测] 节点 %s 状态良好: %v", n.Domain, n.latency.Round(time.Millisecond))
				}
				n.mu.Unlock()

			}(node)
		}
		wg.Wait()
		<-ticker.C
	}
}

// [v28.0] 新增：重连熔断器
var (
	reconnectMux      sync.Mutex
	reconnectCount    int
	lastReconnectTime time.Time
)

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	
	// [熔断器] 检查是否需要冷静
	reconnectMux.Lock()
	if reconnectCount > 5 && time.Since(lastReconnectTime) < 3*time.Second {
		reconnectMux.Unlock()
		log.Printf("[Core] [熔断] 3秒内重连次数过多，进入冷静期 5 秒...")
		time.Sleep(5 * time.Second)
	} else if time.Since(lastReconnectTime) >= 3*time.Second {
		reconnectCount = 0 // 重置计数器
	}
	reconnectCount++
	lastReconnectTime = time.Now()
	reconnectMux.Unlock()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	var target string; var err error; var firstFrame []byte; var mode int
	switch buf[0] { case 0x05: target, err = handleSOCKS5(conn, inboundTag); mode = 1; default: target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag) }
	
	if err != nil { return }

	wsConn, disconnectMode, rtt, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil { return }

	finalMode := disconnectMode
	if shouldDisableDisconnect(target) {
		finalMode = MODE_KEEP
	}

	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }; if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	pipeDirect(conn, wsConn, target, finalMode, rtt)
}

func match(rule Rule, target string) bool {
	targetHost, _, _ := net.SplitHostPort(target); if targetHost == "" { targetHost = target }
	switch rule.Type {
	case MatchTypeDomain: return targetHost == rule.Node.Domain
	case MatchTypeRegex: return rule.CompiledRegex.MatchString(targetHost)
	default: return strings.Contains(target, rule.Value)
	}
}

// [v28.0] 智能负载均衡
func selectSmartNode(nodes []*Node) *Node {
	if len(nodes) == 0 { return nil }
	if len(nodes) == 1 { return nodes[0] }

	var aliveNodes []*Node
	for _, n := range nodes {
		n.mu.RLock()
		if n.alive {
			aliveNodes = append(aliveNodes, n)
		}
		n.mu.RUnlock()
	}
	
	if len(aliveNodes) == 0 { // 如果都挂了，随机选一个死马当活马医
		return nodes[rand.Intn(len(nodes))]
	}

	// 按延迟升序排序
	sort.Slice(aliveNodes, func(i, j int) bool {
		aliveNodes[i].mu.RLock()
		aliveNodes[j].mu.RLock()
		defer aliveNodes[i].mu.RUnlock()
		defer aliveNodes[j].mu.RUnlock()
		return aliveNodes[i].latency < aliveNodes[j].latency
	})

	// 返回延迟最低的节点
	return aliveNodes[0]
}

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, int, time.Duration, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, MODE_AUTO, 0, errors.New("settings not found") }
	
	currentMode := MODE_AUTO
	if settings.GlobalKeepAlive { currentMode = MODE_KEEP }

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]; fallback := ""
	if len(parts) > 1 { fallback = parts[1] }

	socks5 := settings.S5 
	if socks5 == "" && settings.ForwarderSettings != nil { socks5 = settings.ForwarderSettings.Socks5Address }

	var finalConn *websocket.Conn
	var finalErr error
	var finalRTT time.Duration

	tryConnectOnce := func() error {
		var targetNode *Node
		ruleHit := false
		
		for _, rule := range routingMap {
			if match(rule, target) {
				targetNode = rule.Node
				if !settings.GlobalKeepAlive { currentMode = rule.DisconnectMode }
				ruleHit = true; break
			}
		}

		if !ruleHit {
			if len(settings.NodePool) > 0 {
				// [v28.0] 启用智能选择
				targetNode = selectSmartNode(settings.NodePool)
			} else { return errors.New("no nodes configured in pool") }
		}

		if targetNode == nil {
			return errors.New("no suitable node found")
		}

		backend := selectBackend(targetNode.Backends, target)
		if backend.IP == "" { backend.IP = settings.ServerIP }

		start := time.Now()
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
		finalRTT = time.Since(start)
		
		if err != nil { return err }
		
		if backend.IP != "" {
			log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real) | Latency: %dms", targetNode.Domain, backend.IP, backend.Port, finalRTT.Milliseconds())
		}
		
		err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
		if err != nil { wsConn.Close(); return err }
		finalConn = wsConn
		return nil
	}

	finalErr = tryConnectOnce()
	if finalErr != nil {
		log.Printf("[Core] Connect failed: %v. Retrying...", finalErr)
		finalErr = tryConnectOnce()
	}
	
	return finalConn, currentMode, finalRTT, finalErr
}

// ... (pipeDirect, selectBackend, dialZeusWebSocket, formatBytes, sendNanoHeaderV2, handleSOCKS5, handleHTTP, parseServerAddr are unchanged from v27.3)
func pipeDirect(local net.Conn, ws *websocket.Conn, target string, mode int, rtt time.Duration) {
	defer ws.Close()
	defer local.Close()

	var upBytes, downBytes int64
	startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	var once sync.Once
	closeConns := func() { once.Do(func() { ws.Close(); local.Close(); }) }

	// 智能超时
	smartTimeout := rtt * 3
	if smartTimeout < 300 * time.Millisecond {
		smartTimeout = 300 * time.Millisecond
	} else if smartTimeout > 2 * time.Second {
		smartTimeout = 2 * time.Second
	}

	dynamicLimit := getDynamicThreshold()

	enableDisconnect := false
	logPrefix := "[智能]"
	switch mode {
	case MODE_KEEP:
		enableDisconnect = false
		logPrefix = "[长连]"
		log.Printf("[Core] %s %s 命中长连接模式，禁用断流。", logPrefix, target)
	case MODE_CUT:
		enableDisconnect = true
		logPrefix = "[短连]"
	case MODE_AUTO:
		if shouldDisableDisconnect(target) {
			enableDisconnect = false
			logPrefix = "[豁免]"
			log.Printf("[Core] %s %s 命中豁免名单/gRPC，自动保活。", logPrefix, target)
		} else {
			enableDisconnect = true
			log.Printf("[Core] %s %s 启用智能流控 (阈值: %.2fMB, 超时: %dms)。", logPrefix, float64(dynamicLimit)/1024/1024, smartTimeout.Milliseconds())
		}
	}

	// Downlink
	go func() {
		defer wg.Done()
		defer closeConns()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		
		for {
			ws.SetReadDeadline(time.Now().Add(smartTimeout)) 
			mt, r, err := ws.NextReader()
			if err != nil { return }

			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				if err != nil { return }
				
				newDownBytes := atomic.AddInt64(&downBytes, n)
				
				if enableDisconnect && newDownBytes > dynamicLimit {
					log.Printf("[Core] %s %s 完成使命 (%.1f MB)，主动重置。", logPrefix, float64(newDownBytes)/1024/1024)
					return
				}
			}
		}
	}() 

	// Uplink
	go func() {
		defer wg.Done()
		defer closeConns()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				atomic.AddInt64(&upBytes, int64(n))
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { return }
			}
			if err != nil { return }
		}
	}()

	wg.Wait()
	duration := time.Since(startTime)
	log.Printf("[Stats] %s | Up: %s | Down: %s | T: %v", target, formatBytes(upBytes), formatBytes(downBytes), duration.Round(time.Millisecond))
}

func selectBackend(backends []Backend, key string) Backend { if len(backends) == 0 { return Backend{} }; if len(backends) == 1 { return backends[0] }; totalWeight := 0; for _, b := range backends { totalWeight += b.Weight }; h := md5.Sum([]byte(key)); hashVal := binary.BigEndian.Uint64(h[:8]); if totalWeight == 0 { return backends[int(hashVal%uint64(len(backends)))] }; targetVal := int(hashVal % uint64(totalWeight)); currentWeight := 0; for _, b := range backends { currentWeight += b.Weight; if targetVal < currentWeight { return b } }; return backends[0] }
func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) { sniHost, sniPort, err := net.SplitHostPort(sni); if err != nil { sniHost, sniPort = sni, "443" }; dialPort := sniPort; if backend.Port != "" { dialPort = backend.Port }; wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token)); requestHeader := http.Header{}; requestHeader.Add("Host", sniHost); requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"); dialer := websocket.Dialer{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, HandshakeTimeout: 5 * time.Second }; if backend.IP != "" { dialer.NetDial = func(network, addr string) (net.Conn, error) { return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) } }; conn, resp, err := dialer.Dial(wsURL, requestHeader); if err != nil { if resp != nil { return nil, fmt.Errorf("handshake failed with status %d", resp.StatusCode) }; return nil, err }; return conn, nil }
func formatBytes(b int64) string { const unit = 1024; if b < unit { return fmt.Sprintf("%d B", b) }; div, exp := int64(unit), 0; for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }; return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp]) }
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error { host, portStr, _ := net.SplitHostPort(target); var port uint16; fmt.Sscanf(portStr, "%d", &port); hostBytes, s5Bytes, fbBytes := []byte(host), []byte(s5), []byte(fb); if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 { return errors.New("address length exceeds 255 bytes") }; buf := new(bytes.Buffer); buf.WriteByte(byte(len(hostBytes))); buf.Write(hostBytes); portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, port); buf.Write(portBytes); buf.WriteByte(byte(len(s5Bytes))); if len(s5Bytes) > 0 { buf.Write(s5Bytes) }; buf.WriteByte(byte(len(fbBytes))); if len(fbBytes) > 0 { buf.Write(fbBytes) }; if len(payload) > 0 { buf.Write(payload) }; return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()) }
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path, addr = addr[idx:], addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host, port, err = addr, "443", nil }; return }
