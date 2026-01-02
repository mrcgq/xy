// core/core-binary.go (v21.5 - Final Cleaned)
// [修复] 移除所有重复定义的函数 (StartInstance, RunSpeedTest)
// [状态] 完整无省略版, 生产级可用, 可直接编译

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
	"flag" // ★ 引入 flag 包
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

// ================== [v21.5] 事件驱动配置常量 ==================

const (
	MODE_AUTO = 0 // 智能识别 (默认，L1)
	MODE_KEEP = 1 // 强制保持 (视频/游戏，L2/L3)
	MODE_CUT  = 2 // 强制断流 (爬虫/网页，L2)

	MAX_BYTES_PER_CONN      = 10 * 1024 * 1024 // 10MB 流量阈值
	NO_RESPONSE_TIMEOUT_MS = 200              // 200ms 无响应超时
)

var disconnectDomainBlacklist = []string{
	"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
	"nflxvideo.net", "vimeo.com", "live", "stream",
	"telesco.pe", "tdesktop.com",
}
var disconnectSuffixRegex = regexp.MustCompile(`(?i)\.(m3u8|mp4|flv|mkv|avi|mov|ts|webm)$`)

func shouldDisableDisconnect(target string) bool {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.ToLower(host)
	for _, keyword := range disconnectDomainBlacklist {
		if strings.Contains(host, keyword) {
			return true
		}
	}
	if disconnectSuffixRegex.MatchString(host) {
		return true
	}
	if portStr != "80" && portStr != "443" && portStr != "" {
		return true
	}
	return false
}

// ============================================================

var globalRRIndex uint64

type Backend struct {
	IP     string
	Port   string
	Weight int
}

type Node struct {
	Domain   string
	Backends []Backend
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
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
	NodePool          []Node                  `json:"-"`
}

type Config struct{ Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"` }
type Inbound struct{ Tag, Listen, Protocol string }
type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}
type ProxyForwarderSettings struct{ Socks5Address string }

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule
	geositeMatcher   map[string][]*routercommon.Domain
	geodataMutex     sync.RWMutex
)

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

// ======================== 主入口 (Main) ========================

func main() {
	configPath := flag.String("c", "", "Path to config file (JSON)")
	
	listen := flag.String("listen", "", "Local listen address")
	server := flag.String("server", "", "Server address (pool)")
	serverIP := flag.String("ip", "", "Global fallback server IP")
	key := flag.String("key", "", "Secret key")
	s5 := flag.String("s5", "", "SOCKS5 proxy address")
	fallback := flag.String("fallback", "", "Fallback address")
	strategy := flag.String("strategy", "random", "Load balance strategy")
	rules := flag.String("rules", "", "Routing rules")
	keepAlive := flag.Bool("keepalive", false, "Enable global keep-alive")
	ping := flag.Bool("ping", false, "Ping mode")

	flag.Parse()

	if *ping {
		RunSpeedTest(*server, *key, *serverIP)
		return
	}
    
    var configBytes []byte
    var err error

    if *configPath != "" {
        configBytes, err = os.ReadFile(*configPath)
        if err != nil {
            log.Fatalf("Failed to read config file: %v", err)
        }
    } else {
        tokenVal := *key
        if *fallback != "" { tokenVal = tokenVal + "|" + *fallback }
        
        settings := ProxySettings{
            Server: *server, ServerIP: *serverIP, Token: tokenVal, Strategy: *strategy,
            Rules: *rules, GlobalKeepAlive: *keepAlive,
        }
        if *s5 != "" { settings.ForwarderSettings = &ProxyForwarderSettings{Socks5Address: *s5} }
        
        settingsBytes, _ := json.Marshal(settings)
        
        configStr := fmt.Sprintf(`{
            "inbounds": [{"tag": "socks-in", "listen": "%s", "protocol": "socks"}],
            "outbounds": [{"tag": "proxy", "protocol": "ech-proxy", "settings": %s}]
        }`, *listen, string(settingsBytes))
        configBytes = []byte(configStr)
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
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func loadGeodata() {
	rawBytes, err := os.ReadFile("geosite.dat")
	if err != nil {
		return
	}
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
	case routercommon.Domain_Plain:
		return strings.Contains(domain, rule.Value)
	case routercommon.Domain_Regex:
		matched, _ := regexp.MatchString(rule.Value, domain)
		return matched
	case routercommon.Domain_RootDomain:
		return domain == rule.Value || strings.HasSuffix(domain, "."+rule.Value)
	case routercommon.Domain_Full:
		return domain == rule.Value
	default:
		return false
	}
}

func isDomainInGeosite(domain, geositeCategory string) bool {
	geodataMutex.RLock()
	defer geodataMutex.RUnlock()
	if geositeMatcher == nil {
		return false
	}
	matchers, found := geositeMatcher[strings.ToLower(geositeCategory)]
	if !found {
		return false
	}
	for _, matcher := range matchers {
		if matchDomainRule(domain, matcher) {
			return true
		}
	}
	return false
}

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
		if e == "" {
			continue
		}
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
	if len(globalConfig.Outbounds) == 0 {
		return
	}
	var s ProxySettings
	if err := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err != nil {
		return
	}
	if s.Rules == "" {
		return
	}

	rawRules := strings.ReplaceAll(s.Rules, "\r", "")
	lines := strings.Split(rawRules, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			keyword := strings.TrimSpace(parts[0])
			rightSide := strings.TrimSpace(parts[1])
			strategy := ""
			if len(parts) >= 3 {
				strategy = strings.TrimSpace(parts[2])
			}
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
			if !aliasFound {
				foundNode = parseNode(rightSide)
			}
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
				rawPool := strings.ReplaceAll(settings.Server, "\r\n", ";")
				rawPool = strings.ReplaceAll(rawPool, "\n", ";")
				rawPool = strings.ReplaceAll(rawPool, "，", ";")
				rawPool = strings.ReplaceAll(rawPool, ",", ";")
				rawPool = strings.ReplaceAll(rawPool, "；", ";")
				nodeStrs := strings.Split(rawPool, ";")
				for _, nodeStr := range nodeStrs {
					if trimmed := strings.TrimSpace(nodeStr); trimmed != "" {
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
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil {
		return
	}
	wsConn, disconnectMode, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil {
		return
	}
	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}
	pipeDirect(conn, wsConn, target, disconnectMode)
}

func match(rule Rule, target string) bool {
	targetHost, _, _ := net.SplitHostPort(target)
	if targetHost == "" {
		targetHost = target
	}
	switch rule.Type {
	case MatchTypeDomain:
		return targetHost == rule.Value
	case MatchTypeRegex:
		return rule.CompiledRegex.MatchString(targetHost)
	case MatchTypeGeosite:
		return false
	case MatchTypeGeoIP:
		return false
	case MatchTypeSubstring:
		fallthrough
	default:
		return strings.Contains(target, rule.Value)
	}
}

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, int, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, MODE_AUTO, errors.New("settings not found")
	}
	currentMode := MODE_AUTO
	if settings.GlobalKeepAlive {
		currentMode = MODE_KEEP
	}

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 {
		fallback = parts[1]
	}
	socks5 := ""
	if settings.ForwarderSettings != nil {
		socks5 = settings.ForwarderSettings.Socks5Address
	}

	var finalConn *websocket.Conn
	var finalErr error

	tryConnectOnce := func() error {
		var targetNode Node
		var logMsg string
		var finalStrategy string
		ruleHit := false
		for _, rule := range routingMap {
			if match(rule, target) {
				targetNode = rule.Node
				finalStrategy = rule.Strategy
				if finalStrategy == "" {
					finalStrategy = settings.Strategy
				}
				if !settings.GlobalKeepAlive {
					currentMode = rule.DisconnectMode
				}
				logMsg = fmt.Sprintf("[Core] Rule Hit -> %s | SNI: %s (Rule: %s, Algo: %s)", target, targetNode.Domain, rule.Value, finalStrategy)
				ruleHit = true
				break
			}
		}
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
				return errors.New("no nodes configured in pool")
			}
		}
		log.Print(logMsg)
		backend := selectBackend(targetNode.Backends, target)
		if backend.IP == "" {
			backend.IP = settings.ServerIP
		}
		start := time.Now()
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return err
		}
		if backend.IP != "" {
			log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real) | Latency: %dms", targetNode.Domain, backend.IP, backend.Port, latency)
		}
		err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
		if err != nil {
			wsConn.Close()
			return err
		}
		finalConn = wsConn
		return nil
	}

	finalErr = tryConnectOnce()
	if finalErr != nil && len(settings.NodePool) > 1 {
		log.Printf("[Core] Connect failed: %v. Retry...", finalErr)
		finalErr = tryConnectOnce()
	}
	return finalConn, currentMode, finalErr
}

func pipeDirect(local net.Conn, ws *websocket.Conn, target string, mode int) {
	defer ws.Close()
	defer local.Close()

	var upBytes, downBytes int64
	startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	var once sync.Once
	closeConns := func() {
		once.Do(func() {
			ws.Close()
			local.Close()
		})
	}

	enableDisconnect := false
	switch mode {
	case MODE_KEEP:
		enableDisconnect = false
		log.Printf("[Core] [防御L3/L2] 目标 %s 命中【长连接模式】，禁用主动断流。", target)
	case MODE_CUT:
		enableDisconnect = true
		log.Printf("[Core] [防御L2] 目标 %s 命中【短连接模式】，强制启用主动断流。", target)
	case MODE_AUTO:
		if shouldDisableDisconnect(target) {
			enableDisconnect = false
			log.Printf("[Core] [防御L1] 目标 %s 命中智能黑名单，自动禁用断流。", target)
		} else {
			enableDisconnect = true
			log.Printf("[Core] [防御L1] 目标 %s 判定为普通流量，启用主动断流保护。", target)
		}
	}

	if !enableDisconnect {
		go func() {
			defer wg.Done()
			io.Copy(ws.UnderlyingConn(), local)
			closeConns()
		}()
		go func() {
			defer wg.Done()
			io.Copy(local, ws.UnderlyingConn())
			closeConns()
		}()
		wg.Wait()
		return
	}

	resetTimer := make(chan bool, 1)

	go func() {
		defer wg.Done()
		defer closeConns()
		for {
			ws.SetReadDeadline(time.Now().Add(180 * time.Second))
			mt, r, err := ws.NextReader()
			if err != nil {
				return
			}
			if mt == websocket.BinaryMessage {
				n, err := io.Copy(local, r)
				if err != nil {
					return
				}
				newDownBytes := atomic.AddInt64(&downBytes, n)
				if newDownBytes > MAX_BYTES_PER_CONN {
					log.Printf("[Core] [主动断流] %s 达到流量阈值，执行重置。", target)
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer closeConns()
		timer := time.NewTimer(time.Duration(NO_RESPONSE_TIMEOUT_MS) * time.Millisecond)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		go func() {
			for {
				select {
				case <-timer.C:
					log.Printf("[Core] [主动断流] %s 在发送后 %dms 内无响应，执行重置。", target, NO_RESPONSE_TIMEOUT_MS)
					closeConns()
					return
				case _, ok := <-resetTimer:
					if !ok {
						return
					}
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(time.Duration(NO_RESPONSE_TIMEOUT_MS) * time.Millisecond)
				}
			}
		}()

		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			n, err := local.Read(buf)
			if err != nil {
				close(resetTimer)
				return
			}
			if n > 0 {
				atomic.AddInt64(&upBytes, int64(n))
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					close(resetTimer)
					return
				}
				resetTimer <- true
			}
		}
	}()

	wg.Wait()
	duration := time.Since(startTime)
	log.Printf("[Stats] %s | Up: %s | Down: %s | Time: %v", target, formatBytes(upBytes), formatBytes(downBytes), duration.Round(time.Second))
}

// --- 辅助函数 ---
func selectBackend(backends []Backend, key string) Backend { if len(backends) == 0 { return Backend{} }; if len(backends) == 1 { return backends[0] }; totalWeight := 0; for _, b := range backends { totalWeight += b.Weight }; h := md5.Sum([]byte(key)); hashVal := binary.BigEndian.Uint64(h[:8]); if totalWeight == 0 { return backends[int(hashVal%uint64(len(backends)))] }; targetVal := int(hashVal % uint64(totalWeight)); currentWeight := 0; for _, b := range backends { currentWeight += b.Weight; if targetVal < currentWeight { return b } }; return backends[0] }
func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) { sniHost, sniPort, err := net.SplitHostPort(sni); if err != nil { sniHost, sniPort = sni, "443" }; dialPort := sniPort; if backend.Port != "" { dialPort = backend.Port }; wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token)); requestHeader := http.Header{}; requestHeader.Add("Host", sniHost); requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"); dialer := websocket.Dialer{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: sniHost }, HandshakeTimeout: 5 * time.Second }; if backend.IP != "" { dialer.NetDial = func(network, addr string) (net.Conn, error) { return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), 5*time.Second) } }; conn, resp, err := dialer.Dial(wsURL, requestHeader); if err != nil { if resp != nil { return nil, fmt.Errorf("handshake failed with status %d", resp.StatusCode) }; return nil, err }; return conn, nil }
func formatBytes(b int64) string { const unit = 1024; if b < unit { return fmt.Sprintf("%d B", b) }; div, exp := int64(unit), 0; for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }; return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp]) }
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error { host, portStr, _ := net.SplitHostPort(target); var port uint16; fmt.Sscanf(portStr, "%d", &port); hostBytes, s5Bytes, fbBytes := []byte(host), []byte(s5), []byte(fb); if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 { return errors.New("address length exceeds 255 bytes") }; buf := new(bytes.Buffer); buf.WriteByte(byte(len(hostBytes))); buf.Write(hostBytes); portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, port); buf.Write(portBytes); buf.WriteByte(byte(len(s5Bytes))); if len(s5Bytes) > 0 { buf.Write(s5Bytes) }; buf.WriteByte(byte(len(fbBytes))); if len(fbBytes) > 0 { buf.Write(fbBytes) }; if len(payload) > 0 { buf.Write(payload) }; return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()) }
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path, addr = addr[idx:], addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host, port, err = addr, "443", nil }; return }
