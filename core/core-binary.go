// core/core-binary.go (v25.0 - Diamond Edition)
// [版本] v25.0 无缝并发版 (Zero-Wait)
// [特性] 空中加油(Pre-dialing) | 动态阈值 | RTT感知 | 0ms切换
// [状态] 生产级可用，架构升级

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

// ================== [v25.0] 配置常量 ==================

const (
	MODE_AUTO = 0
	MODE_KEEP = 1
	MODE_CUT  = 2
)

// [智能核心] 动态阈值：8MB ~ 12MB
func getDynamicThreshold() int64 {
	base := int64(8 * 1024 * 1024)
	jitter := rand.Int63n(4 * 1024 * 1024)
	return base + jitter
}

var disconnectDomainBlacklist = []string{
	"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
	"nflxvideo.net", "vimeo.com", "live", "stream",
	"telesco.pe", "tdesktop.com",
}
var disconnectSuffixRegex = regexp.MustCompile(`(?i)\.(m3u8|mp4|flv|mkv|avi|mov|ts|webm)$`)

func shouldDisableDisconnect(target string) bool {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil { host = target }
	host = strings.ToLower(host)
	for _, keyword := range disconnectDomainBlacklist {
		if strings.Contains(host, keyword) { return true }
	}
	if disconnectSuffixRegex.MatchString(host) { return true }
	if portStr != "80" && portStr != "443" && portStr != "" { return true }
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

// [v25.0 架构升级] 连接胶囊：封装预连接所需的所有信息
type ConnCapsule struct {
	Conn    *websocket.Conn
	Mode    int
	RTT     time.Duration
	Err     error
}

// ======================== 主入口 (Main) ========================

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
	log.Println("[Core] [系统初始化] 正在加载 v25.0 (无缝并发版)...")
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

	// ================= [v25 核心架构变化] =================
	
	// 预连接通道：用于存放下一个准备好的连接
	// 容量为1，避免无限创建
	nextConnChan := make(chan ConnCapsule, 1)

	// 定义拨号器函数：封装拨号逻辑，便于复用和异步调用
	dialer := func() ConnCapsule {
		ws, dMode, rtt, e := connectNanoTunnel(target, "proxy", firstFrame)
		return ConnCapsule{Conn: ws, Mode: dMode, RTT: rtt, Err: e}
	}

	// 1. 首次拨号 (同步)
	firstCapsule := dialer()
	if firstCapsule.Err != nil { return }

	// 向客户端发送握手响应
	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	currentCapsule := firstCapsule

	for {
		// 触发预拨号的信号灯 (One-shot signal)
		triggerPreDial := make(chan bool, 1)
		
		// 启动异步监视器：一旦触发信号，立即拨号下一个
		go func() {
			select {
			case <-triggerPreDial:
				// [空中加油] 收到信号，立即开始拨号下一个连接
				nextConnChan <- dialer()
			case <-time.After(30 * time.Minute): // 防止 goroutine 泄露的保底
				return
			}
		}()

		// 执行数据管道，传入触发器
		// pipeDirect 现在负责在流量达标时调用 triggerPreDial <- true
		pipeDirect(conn, currentCapsule.Conn, target, currentCapsule.Mode, currentCapsule.RTT, triggerPreDial)

		// 当前连接结束，检查是否因错误退出
		// 如果 pipeDirect 正常返回，说明触发了轮换
		// 此时 nextConnChan 里应该正在拨号或已经拨号完成
		
		select {
		case nextCapsule := <-nextConnChan:
			// [无缝切换] 拿到下一个连接
			if nextCapsule.Err != nil {
				// 如果预连接失败，尝试同步重试一次，或者直接退出
				return
			}
			currentCapsule = nextCapsule
			// 循环继续，立即使用新连接，0等待
		default:
			// 这种情况一般不应该发生，除非 pipeDirect 异常退出
			return
		}
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

// [v25.0] 封装后的拨号函数
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
			// 在 v25 中减少日志频率，避免并发拨号刷屏
			// log.Printf(...) 
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

// [v25.0] pipeDirect 升级：支持预拨号触发器
func pipeDirect(local net.Conn, ws *websocket.Conn, target string, mode int, rtt time.Duration, preDialTrigger chan<- bool) {
	defer ws.Close()
	// 注意：不能 defer local.Close()，因为 local 连接要在多个 WS 连接间复用！
	// 只有在 pipeDirect 彻底出错或者不需要重连时，才由外层关闭 local

	var upBytes, downBytes int64
	// startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	
	// 控制内部 goroutine 退出的信号
	quit := make(chan bool)

	// 1. 智能超时 (RTT * 4)
	smartTimeout := rtt * 4
	if smartTimeout < 300 * time.Millisecond {
		smartTimeout = 300 * time.Millisecond
	} else if smartTimeout > 5 * time.Second {
		smartTimeout = 5 * time.Second
	}

	// 2. 动态阈值
	dynamicLimit := getDynamicThreshold()
	// 预拨号阈值 (80%)
	preDialLimit := int64(float64(dynamicLimit) * 0.8)

	enableDisconnect := false
	// logPrefix := "[智能]"
	switch mode {
	case MODE_KEEP: enableDisconnect = false; // logPrefix = "[长连]"
	case MODE_CUT: enableDisconnect = true; // logPrefix = "[短连]"
	case MODE_AUTO:
		if shouldDisableDisconnect(target) {
			enableDisconnect = false; // logPrefix = "[自动]"
		} else {
			enableDisconnect = true
		}
	}
	
	// 标记是否已触发预拨号，避免重复触发
	var handoffTriggered int32 = 0

	// Downlink: WS -> TCP
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		
		for {
			ws.SetReadDeadline(time.Now().Add(smartTimeout)) 
			mt, r, err := ws.NextReader()
			if err != nil { 
				// WS 断开，通知 uplink 退出
				close(quit)
				return 
			}

			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				if err != nil { close(quit); return } // 本地连接断开，彻底结束
				
				newDownBytes := atomic.AddInt64(&downBytes, n)
				
				if enableDisconnect {
					// [阶段一] 空中加油：达到 80% 流量，通知外层拨号
					if atomic.CompareAndSwapInt32(&handoffTriggered, 0, 1) {
						if newDownBytes > preDialLimit {
							select {
							case preDialTrigger <- true:
							default:
							}
						} else {
							atomic.StoreInt32(&handoffTriggered, 0) // 没达到，还原标记
						}
					}

					// [阶段二] 寿命终结
					if newDownBytes > dynamicLimit {
						// 确保触发了预拨号 (防止流量瞬间暴增跳过阶段一)
						select {
						case preDialTrigger <- true:
						default:
						}
						// 退出循环，关闭 WS，外层 loop 会接管 local 并使用 nextConn
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
				return // 下行已断，上行随之结束
			default:
				// 设置一个极短的 ReadDeadline 以便能响应 quit 信号?
				// 不，local 是 net.Conn，不能随便 SetReadDeadline 否则会影响复用
				// 这里依赖 local.Read 的阻塞。如果 WS 断开，我们需要一种方法中断 local.Read 吗？
				// 不需要，因为如果我们要切换连接，local 不需要断。
				// 但是 local.Read 是阻塞的。
				// 这是一个 v25 的技术难点：如何从 pipeDirect 返回但保持 local 不断？
				// 方案：Uplink 协程在 v25 中其实不需要退出！
				// 只要 WS 发送失败，它就会报错。
				
				// 简单处理：使用 SetReadDeadline 轮询检查 quit
				local.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, err := local.Read(buf)
				
				if n > 0 {
					atomic.AddInt64(&upBytes, int64(n))
					if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
						return // WS 写失败，切换
					}
				}
				
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // 超时继续
					}
					// 真正的读取错误（本地断开），彻底结束
					// 这种情况下外层也应该退出
					return 
				}
			}
		}
	}()

	wg.Wait()
}

func selectBackend(backends []Backend, key string) Backend { if len(backends) == 0 { return Backend{} }; if len(backends) == 1 { return backends[0] }; totalWeight := 0; for _, b := range backends { totalWeight += b.Weight }; h := md5.Sum([]byte(key)); hashVal := binary.BigEndian.Uint64(h[:8]); if totalWeight == 0 { return backends[int(hashVal%uint64(len(backends)))] }; targetVal := int(hashVal % uint64(totalWeight)); currentWeight := 0; for _, b := range backends { currentWeight += b.Weight; if targetVal < currentWeight { return b } }; return backends[0] }
func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) { sniHost, sniPort, err := net.SplitHostPort(sni); if err != nil { sniHost, sniPort = sni, "443" }; dialPort := sniPort; if backend.Port != "" { dialPort = backend.Port }; wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token)); requestHeader := http.Header{}; requestHeader.Add("Host", sniHost); requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"); dialer := websocket.Dialer{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, HandshakeTimeout: 5 * time.Second }; if backend.IP != "" { dialer.NetDial = func(network, addr string) (net.Conn, error) { return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) } }; conn, resp, err := dialer.Dial(wsURL, requestHeader); if err != nil { if resp != nil { return nil, fmt.Errorf("handshake failed with status %d", resp.StatusCode) }; return nil, err }; return conn, nil }
func formatBytes(b int64) string { const unit = 1024; if b < unit { return fmt.Sprintf("%d B", b) }; div, exp := int64(unit), 0; for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }; return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp]) }
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error { host, portStr, _ := net.SplitHostPort(target); var port uint16; fmt.Sscanf(portStr, "%d", &port); hostBytes, s5Bytes, fbBytes := []byte(host), []byte(s5), []byte(fb); if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 { return errors.New("address length exceeds 255 bytes") }; buf := new(bytes.Buffer); buf.WriteByte(byte(len(hostBytes))); buf.Write(hostBytes); portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, port); buf.Write(portBytes); buf.WriteByte(byte(len(s5Bytes))); if len(s5Bytes) > 0 { buf.Write(s5Bytes) }; buf.WriteByte(byte(len(fbBytes))); if len(fbBytes) > 0 { buf.Write(fbBytes) }; if len(payload) > 0 { buf.Write(payload) }; return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()) }
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path, addr = addr[idx:], addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host, port, err = addr, "443", nil }; return }
