// core/core-binary.go (v25.3 - Fast Debug Edition)
// [版本] v25.3 急速验证版
// [修改1] 阈值降为 200KB -> 稍微用一下就会触发预拨号
// [修改2] 日志关键词变更 -> 强制显示原始日志，不让客户端翻译
// [用途] 仅供调试观察“空中加油”现象，验证完毕后建议改回 v25.1

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

// ================== [v25.3] 调试配置 ==================

const (
	MODE_AUTO = 0
	MODE_KEEP = 1
	MODE_CUT  = 2
)

// [暴力调试] 阈值设为极低的 200KB ~ 300KB
// 只要打开网页，立马触发多次空中加油
func getDynamicThreshold() int64 {
	base := int64(200 * 1024)          // 200KB
	jitter := rand.Int63n(100 * 1024)  // +0~100KB
	return base + jitter
}

var disconnectDomainBlacklist = []string{
	"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
	"nflxvideo.net", "vimeo.com", "live", "stream",
	"telesco.pe", "tdesktop.com",
}
var disconnectSuffixRegex = regexp.MustCompile(`(?i)\.(m3u8|mp4|flv|mkv|avi|mov|ts|webm)$`)

func shouldDisableDisconnect(target string) bool {
	// [调试版] 即使是视频网站，也强制开启断流，以便观察效果
	// 正常版本请勿保留此逻辑
	return false 
}

// ============================================================

var globalRRIndex uint64

type Backend struct { IP, Port string; Weight int }
type Node struct { Domain string; Backends []Backend }

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
	Node           Node
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
	NodePool          []Node                  `json:"-"`
}

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

type ConnCapsule struct {
	Conn    *websocket.Conn
	Mode    int
	RTT     time.Duration
	Err     error
}

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
		RunSpeedTest(*server, *key, *serverIP)
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
		if err != nil { host, port = addr, "" }
		n.Backends = append(n.Backends, Backend{IP: host, Port: port, Weight: weight})
	}
	return n
}

func parseRules(pool []Node) {
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

			var foundNode Node
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
	log.Println("[Core] [系统初始化] 正在加载 v25.3 (急速验证版)...")
	if checkFileDependency("xray.exe") { log.Println("[Core] [依赖检查] ✅ xray.exe 匹配成功! [智能分流] 模式可用。") } else { log.Println("[Core] [依赖检查] ⚠️ xray.exe 未找到!") }
	if checkFileDependency("geosite.dat") { log.Println("[Core] [依赖检查] ✅ geosite.dat 匹配成功!"); loadGeodata() } else { log.Println("[Core] [依赖检查] ⚠️ geosite.dat 未找到!") }
	if checkFileDependency("geoip.dat") { log.Println("[Core] [依赖检查] ✅ geoip.dat 匹配成功!") } else { log.Println("[Core] [依赖检查] ⚠️ geoip.dat 未找到!") }
	log.Println("------------------------------------")
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds(); if s, ok := proxySettingsMap["proxy"]; ok { parseRules(s.NodePool) }
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]; listener, err := net.Listen("tcp", inbound.Listen); if err != nil { return nil, err }
	mode := "Single Node"; if s, ok := proxySettingsMap["proxy"]; ok { if len(s.NodePool) > 1 { mode = fmt.Sprintf("Zeus Pool (%d nodes)", len(s.NodePool)) } else if len(s.NodePool) == 1 { mode = fmt.Sprintf("Zeus Single") }; if len(routingMap) > 0 { mode += fmt.Sprintf(" + Rules") } }
	if s, ok := proxySettingsMap["proxy"]; ok && s.GlobalKeepAlive { log.Println("[Core] ★★★ 全局沉浸模式 (L3) 已开启 ★★★") }
	log.Printf("[Core] Xlink Engine v25 Listening on %s [%s]", inbound.Listen, mode)
	go func() { for { conn, err := listener.Accept(); if err != nil { break }; go handleGeneralConnection(conn, inbound.Tag) } }()
	return listener, nil
}

type TestResult struct { Node Node; Delay time.Duration; Error error }
func pingNode(node Node, token, globalIP string, results chan<- TestResult) { startTime := time.Now(); backend := selectBackend(node.Backends, ""); if backend.IP == "" { backend.IP = globalIP }; conn, err := dialZeusWebSocket(node.Domain, backend, token); if err != nil { results <- TestResult{Node: node, Error: err}; return }; conn.Close(); delay := time.Since(startTime); results <- TestResult{Node: node, Delay: delay} }
func RunSpeedTest(serverAddr, token, globalIP string) { rawPool := strings.ReplaceAll(serverAddr, "\r\n", ";"); rawPool = strings.ReplaceAll(rawPool, "\n", ";"); nodeStrs := strings.Split(rawPool, ";"); var nodes []Node; for _, nodeStr := range nodeStrs { if trimmed := strings.TrimSpace(nodeStr); trimmed != "" { nodes = append(nodes, parseNode(trimmed)) } }; if len(nodes) == 0 { log.Println("No valid nodes found."); return }; var wg sync.WaitGroup; results := make(chan TestResult, len(nodes)); for _, node := range nodes { wg.Add(1); go func(n Node) { defer wg.Done(); parts := strings.SplitN(token, "|", 2); pingNode(n, parts[0], globalIP, results) }(node) }; wg.Wait(); close(results); var successful, failed []TestResult; for res := range results { if res.Error == nil { successful = append(successful, res) } else { failed = append(failed, res) } }; sort.Slice(successful, func(i, j int) bool { return successful[i].Delay < successful[j].Delay }); fmt.Println("\nPing Test Report"); for i, res := range successful { fmt.Printf("%d. %-40s | Delay: %v\n", i+1, formatNode(res.Node), res.Delay.Round(time.Millisecond)) }; if len(failed) > 0 { fmt.Println("\nFailed Nodes"); for _, res := range failed { fmt.Printf("- %-40s | Error: %v\n", formatNode(res.Node), res.Error) } }; fmt.Println("\n------------------------------------") }
func formatNode(n Node) string { res := n.Domain; if len(n.Backends) > 0 { res += "#..."; }; return res }

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	
	var target string
	var err error
	var firstFrame []byte
	var mode int // 1:Socks5, 2:HTTP

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	
	if err != nil { return }
	
	nextConnChan := make(chan ConnCapsule, 1)

	dialer := func(isPreDial bool) ConnCapsule {
		ws, dMode, rtt, e := connectNanoTunnel(target, "proxy", firstFrame, isPreDial)
		return ConnCapsule{Conn: ws, Mode: dMode, RTT: rtt, Err: e}
	}

	firstCapsule := dialer(false)
	if firstCapsule.Err != nil { return }

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	currentCapsule := firstCapsule

	for {
		triggerPreDial := make(chan bool, 1)
		
		go func() {
			select {
			case <-triggerPreDial:
				// [空中加油] 触发
				nextConnChan <- dialer(true)
			case <-time.After(30 * time.Minute):
				return
			}
		}()

		needSwitch := pipeDirect(conn, currentCapsule.Conn, target, currentCapsule.Mode, currentCapsule.RTT, triggerPreDial)

		if !needSwitch {
			return 
		}

		nextCapsule := <-nextConnChan
		
		if nextCapsule.Err != nil {
			return
		}
		currentCapsule = nextCapsule
	}
}

func match(rule Rule, target string) bool {
	targetHost, _, _ := net.SplitHostPort(target); if targetHost == "" { targetHost = target }
	switch rule.Type {
	case MatchTypeDomain: return targetHost == rule.Value
	case MatchTypeRegex: return rule.CompiledRegex.MatchString(targetHost)
	default: return strings.Contains(target, rule.Value)
	}
}

func connectNanoTunnel(target string, outboundTag string, payload []byte, isPreDial bool) (*websocket.Conn, int, time.Duration, error) {
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
		var targetNode Node
		var finalStrategy string
		ruleHit := false
		
		for _, rule := range routingMap {
			if match(rule, target) {
				targetNode = rule.Node; finalStrategy = rule.Strategy; if finalStrategy == "" { finalStrategy = settings.Strategy }
				if !settings.GlobalKeepAlive { currentMode = rule.DisconnectMode }
				ruleHit = true; break
			}
		}

		if !ruleHit {
			if len(settings.NodePool) > 0 {
				finalStrategy = settings.Strategy
				switch finalStrategy {
				case "rr": idx := atomic.AddUint64(&globalRRIndex, 1); targetNode = settings.NodePool[idx%uint64(len(settings.NodePool))]
				case "hash": h := md5.Sum([]byte(target)); hashVal := binary.BigEndian.Uint64(h[:8]); targetNode = settings.NodePool[hashVal%uint64(len(settings.NodePool))]
				default: targetNode = settings.NodePool[rand.Intn(len(settings.NodePool))]
				}
			} else { return errors.New("no nodes configured") }
		}

		backend := selectBackend(targetNode.Backends, target)
		if backend.IP == "" { backend.IP = settings.ServerIP }

		start := time.Now()
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
		finalRTT = time.Since(start)
		
		if err != nil { return err }
		
		if backend.IP != "" {
			// [v25.3 暴力显形] 
			// 将关键词改成 TunnelV25 (首连) 和 PreConn (空连)
			// 这样 C 客户端因为匹配不到 "Tunnel ->" (注意空格) 而停止翻译，直接吐出原文
			keyword := "TunnelV25" 
			prefix := ""
			if isPreDial {
				keyword = "PreConn" 
				prefix = "[空中加油] "
			}
			log.Printf("[Core] %s%s -> %s (SNI) >>> %s:%s (Real) | Latency: %dms", prefix, keyword, targetNode.Domain, backend.IP, backend.Port, finalRTT.Milliseconds())
		}
		
		err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
		if err != nil { wsConn.Close(); return err }
		finalConn = wsConn
		return nil
	}

	finalErr = tryConnectOnce()
	if finalErr != nil && len(settings.NodePool) > 1 {
		finalErr = tryConnectOnce()
	}
	
	return finalConn, currentMode, finalRTT, finalErr
}

func pipeDirect(local net.Conn, ws *websocket.Conn, target string, mode int, rtt time.Duration, preDialTrigger chan<- bool) bool {
	defer ws.Close()
	var upBytes, downBytes int64
	var wg sync.WaitGroup
	wg.Add(2)
	quit := make(chan bool)

	// 1. 智能超时 (RTT * 4)
	smartTimeout := rtt * 4
	if smartTimeout < 300 * time.Millisecond {
		smartTimeout = 300 * time.Millisecond
	} else if smartTimeout > 5 * time.Second {
		smartTimeout = 5 * time.Second
	}

	// 2. 动态阈值 (200KB)
	dynamicLimit := getDynamicThreshold()
	preDialLimit := int64(float64(dynamicLimit) * 0.8)

	enableDisconnect := false
	switch mode {
	case MODE_KEEP: enableDisconnect = false; 
	case MODE_CUT: enableDisconnect = true; 
	case MODE_AUTO:
		if shouldDisableDisconnect(target) {
			// [调试强制开启] 
			enableDisconnect = true 
		} else {
			enableDisconnect = true
		}
	}
	
	var handoffTriggered int32 = 0
	var needSwitching bool = false

	// Downlink: WS -> TCP
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		
		for {
			ws.SetReadDeadline(time.Now().Add(smartTimeout)) 
			mt, r, err := ws.NextReader()
			if err != nil { close(quit); return }

			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				if err != nil { close(quit); return } 
				
				newDownBytes := atomic.AddInt64(&downBytes, n)
				
				if enableDisconnect {
					// [阶段一] 空中加油
					if atomic.CompareAndSwapInt32(&handoffTriggered, 0, 1) {
						if newDownBytes > preDialLimit {
							select {
							case preDialTrigger <- true:
							default:
							}
						} else {
							atomic.StoreInt32(&handoffTriggered, 0)
						}
					}

					// [阶段二] 寿命终结
					if newDownBytes > dynamicLimit {
						select {
						case preDialTrigger <- true:
						default:
						}
						needSwitching = true
						close(quit)
						return 
					}
				}
			}
		}
	}() 

	// Uplink: TCP -> WS
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			select {
			case <-quit:
				return 
			default:
				local.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, err := local.Read(buf)
				if n > 0 {
					atomic.AddInt64(&upBytes, int64(n))
					if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { return }
				}
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() { continue }
					return 
				}
			}
		}
	}()

	wg.Wait()
	return needSwitching
}

func selectBackend(backends []Backend, key string) Backend { if len(backends) == 0 { return Backend{} }; if len(backends) == 1 { return backends[0] }; totalWeight := 0; for _, b := range backends { totalWeight += b.Weight }; h := md5.Sum([]byte(key)); hashVal := binary.BigEndian.Uint64(h[:8]); if totalWeight == 0 { return backends[int(hashVal%uint64(len(backends)))] }; targetVal := int(hashVal % uint64(totalWeight)); currentWeight := 0; for _, b := range backends { currentWeight += b.Weight; if targetVal < currentWeight { return b } }; return backends[0] }
func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) { sniHost, sniPort, err := net.SplitHostPort(sni); if err != nil { sniHost, sniPort = sni, "443" }; dialPort := sniPort; if backend.Port != "" { dialPort = backend.Port }; wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token)); requestHeader := http.Header{}; requestHeader.Add("Host", sniHost); requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"); dialer := websocket.Dialer{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, HandshakeTimeout: 5 * time.Second }; if backend.IP != "" { dialer.NetDial = func(network, addr string) (net.Conn, error) { return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) } }; conn, resp, err := dialer.Dial(wsURL, requestHeader); if err != nil { if resp != nil { return nil, fmt.Errorf("handshake failed with status %d", resp.StatusCode) }; return nil, err }; return conn, nil }
func formatBytes(b int64) string { const unit = 1024; if b < unit { return fmt.Sprintf("%d B", b) }; div, exp := int64(unit), 0; for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }; return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp]) }
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error { host, portStr, _ := net.SplitHostPort(target); var port uint16; fmt.Sscanf(portStr, "%d", &port); hostBytes, s5Bytes, fbBytes := []byte(host), []byte(s5), []byte(fb); if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 { return errors.New("address length exceeds 255 bytes") }; buf := new(bytes.Buffer); buf.WriteByte(byte(len(hostBytes))); buf.Write(hostBytes); portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, port); buf.Write(portBytes); buf.WriteByte(byte(len(s5Bytes))); if len(s5Bytes) > 0 { buf.Write(s5Bytes) }; buf.WriteByte(byte(len(fbBytes))); if len(fbBytes) > 0 { buf.Write(fbBytes) }; if len(payload) > 0 { buf.Write(payload) }; return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()) }
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path, addr = addr[idx:], addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host, port, err = addr, "443", nil }; return }
