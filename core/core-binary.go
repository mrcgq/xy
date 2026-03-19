// =========================================================================================
// Xlink Core v22.0.0 内核代码 (CF WAF Evasion Kernel)
// [核心改进] Early Data — 协议头 Base64 编码后藏入 Sec-WebSocket-Protocol HTTP 头
//           上行 WebSocket 首帧零协议特征，完美适配 Xlink 22.0 服务端 (CF WAF 深度免杀版)
// [保留] 完整 DNS 解析能力 (DoH, IPv4/IPv6 双栈)
// [保留] TLS/HTTP Sniffing 功能 (恢复原始域名)
// [保留] 入站协议完整支持 IPv6 数据包封装
// [编译] go build -tags binary -ldflags "-s -w" -o xlink-cli-binary.exe
// =========================================================================================

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64" // [v22.0 NEW] Early Data Base64 编码
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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var globalRRIndex uint64

// ======================== DNS 配置与策略 ========================

// DNSStrategy DNS 查询策略
type DNSStrategy string

const (
	DNSStrategyUseIP      DNSStrategy = "UseIP"
	DNSStrategyUseIPv4    DNSStrategy = "UseIPv4"
	DNSStrategyUseIPv6    DNSStrategy = "UseIPv6"
	DNSStrategyPreferIPv6 DNSStrategy = "PreferIPv6"
	DNSStrategyPreferIPv4 DNSStrategy = "PreferIPv4"
)

// DNSConfig 结构体
type DNSConfig struct {
	Enabled          bool        `json:"enabled"`
	Strategy         DNSStrategy `json:"strategy"`
	Servers          []string    `json:"servers"`
	FallbackToRemote bool        `json:"fallback_to_remote"`
	CacheTTL         int         `json:"cache_ttl"`
	TimeoutMs        int         `json:"timeout_ms"`
}

// SniffingConfig 流量嗅探配置
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"dest_override"`
	RouteOnly    bool     `json:"route_only"`
}

// 默认配置
var defaultDNSConfig = DNSConfig{
	Enabled:  true,
	Strategy: DNSStrategyPreferIPv6,
	Servers: []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
	},
	FallbackToRemote: true,
	CacheTTL:         300,
	TimeoutMs:        3000,
}

var defaultSniffingConfig = SniffingConfig{
	Enabled:      true,
	DestOverride: []string{"http", "tls"},
	RouteOnly:    false,
}

// 全局 DNS 缓存
var dnsCache = struct {
	sync.RWMutex
	entries map[string]*dnsCacheEntry
}{
	entries: make(map[string]*dnsCacheEntry),
}

type dnsCacheEntry struct {
	ipv4    []net.IP
	ipv6    []net.IP
	expires time.Time
}

// ======================== DNS 解析模块 ========================

type DNSResolver struct {
	config     DNSConfig
	httpClient *http.Client
}

func NewDNSResolver(config DNSConfig) *DNSResolver {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
			DualStack: true,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	return &DNSResolver{
		config: config,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
		},
	}
}

func (r *DNSResolver) ResolveIP(domain string) (string, error) {
	if !r.config.Enabled {
		return domain, nil
	}
	if ip := net.ParseIP(domain); ip != nil {
		return domain, nil
	}
	if cached := r.getFromCache(domain); cached != "" {
		log.Printf("[DNS] Cache hit: %s -> %s", domain, cached)
		return cached, nil
	}
	ipv4s, ipv6s, err := r.resolveAll(domain)
	if err != nil {
		log.Printf("[DNS] Resolve failed for %s: %v", domain, err)
		return domain, err
	}
	r.saveToCache(domain, ipv4s, ipv6s)
	result := r.selectIP(ipv4s, ipv6s)
	if result == "" {
		return domain, nil
	}
	log.Printf("[DNS] Resolved: %s -> %s (Strategy: %s)", domain, result, r.config.Strategy)
	return result, nil
}

func (r *DNSResolver) ResolveToIPv6(domain string) (string, bool) {
	if !r.config.Enabled {
		return domain, false
	}
	if ip := net.ParseIP(domain); ip != nil {
		return domain, ip.To4() == nil
	}
	dnsCache.RLock()
	if entry, ok := dnsCache.entries[domain]; ok && time.Now().Before(entry.expires) {
		if len(entry.ipv6) > 0 {
			dnsCache.RUnlock()
			return entry.ipv6[0].String(), true
		}
	}
	dnsCache.RUnlock()
	_, ipv6s, err := r.resolveAll(domain)
	if err != nil || len(ipv6s) == 0 {
		return domain, false
	}
	return ipv6s[0].String(), true
}

func (r *DNSResolver) resolveAll(domain string) ([]net.IP, []net.IP, error) {
	var ipv4s, ipv6s []net.IP
	var lastErr error
	for _, server := range r.config.Servers {
		v4, v6, err := r.resolveDoH(server, domain)
		if err == nil && (len(v4) > 0 || len(v6) > 0) {
			return v4, v6, nil
		}
		lastErr = err
	}
	if r.config.FallbackToRemote {
		log.Printf("[DNS] DoH failed, falling back to system DNS for %s", domain)
		ips, err := r.resolveSystem(domain)
		if err == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					ipv4s = append(ipv4s, ip)
				} else {
					ipv6s = append(ipv6s, ip)
				}
			}
			return ipv4s, ipv6s, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (r *DNSResolver) resolveDoH(server, domain string) ([]net.IP, []net.IP, error) {
	var ipv4s, ipv6s []net.IP
	var wg sync.WaitGroup
	var mu sync.Mutex
	queryA := r.config.Strategy != DNSStrategyUseIPv6
	queryAAAA := r.config.Strategy != DNSStrategyUseIPv4
	if queryA {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, err := r.doHQuery(server, domain, "A")
			if err == nil {
				mu.Lock()
				ipv4s = append(ipv4s, ips...)
				mu.Unlock()
			}
		}()
	}
	if queryAAAA {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, err := r.doHQuery(server, domain, "AAAA")
			if err == nil {
				mu.Lock()
				ipv6s = append(ipv6s, ips...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return ipv4s, ipv6s, nil
}

func (r *DNSResolver) doHQuery(server, domain, recordType string) ([]net.IP, error) {
	reqURL := fmt.Sprintf("%s?name=%s&type=%s", server, url.QueryEscape(domain), recordType)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TimeoutMs)*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}
	var result struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, ans := range result.Answer {
		if (recordType == "A" && ans.Type == 1) || (recordType == "AAAA" && ans.Type == 28) {
			if ip := net.ParseIP(ans.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

func (r *DNSResolver) resolveSystem(domain string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TimeoutMs)*time.Millisecond)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func (r *DNSResolver) selectIP(ipv4s, ipv6s []net.IP) string {
	switch r.config.Strategy {
	case DNSStrategyUseIPv6:
		if len(ipv6s) > 0 {
			return ipv6s[0].String()
		}
	case DNSStrategyUseIPv4:
		if len(ipv4s) > 0 {
			return ipv4s[0].String()
		}
	case DNSStrategyPreferIPv6:
		if len(ipv6s) > 0 {
			return ipv6s[0].String()
		}
		if len(ipv4s) > 0 {
			return ipv4s[0].String()
		}
	case DNSStrategyPreferIPv4:
		if len(ipv4s) > 0 {
			return ipv4s[0].String()
		}
		if len(ipv6s) > 0 {
			return ipv6s[0].String()
		}
	default:
		all := append(ipv6s, ipv4s...)
		if len(all) > 0 {
			return all[rand.Intn(len(all))].String()
		}
	}
	return ""
}

func (r *DNSResolver) getFromCache(domain string) string {
	dnsCache.RLock()
	defer dnsCache.RUnlock()
	entry, ok := dnsCache.entries[domain]
	if !ok || time.Now().After(entry.expires) {
		return ""
	}
	return r.selectIP(entry.ipv4, entry.ipv6)
}

func (r *DNSResolver) saveToCache(domain string, ipv4s, ipv6s []net.IP) {
	dnsCache.Lock()
	defer dnsCache.Unlock()
	dnsCache.entries[domain] = &dnsCacheEntry{
		ipv4:    ipv4s,
		ipv6:    ipv6s,
		expires: time.Now().Add(time.Duration(r.config.CacheTTL) * time.Second),
	}
}

// ======================== Sniffing 模块 ========================

type SniffResult struct {
	Domain   string
	Protocol string
	Success  bool
}

type Sniffer struct {
	config SniffingConfig
}

func NewSniffer(config SniffingConfig) *Sniffer {
	return &Sniffer{config: config}
}

func (s *Sniffer) Sniff(data []byte) SniffResult {
	if !s.config.Enabled || len(data) == 0 {
		return SniffResult{Success: false}
	}
	for _, override := range s.config.DestOverride {
		switch override {
		case "tls":
			if result := s.sniffTLS(data); result.Success {
				return result
			}
		case "http":
			if result := s.sniffHTTP(data); result.Success {
				return result
			}
		case "quic":
			if result := s.sniffQUIC(data); result.Success {
				return result
			}
		}
	}
	return SniffResult{Success: false}
}

func (s *Sniffer) sniffTLS(data []byte) SniffResult {
	result := SniffResult{Protocol: "tls", Success: false}
	if len(data) < 5 {
		return result
	}
	if data[0] != 0x16 {
		return result
	}
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0301 || version > 0x0304 {
		if version != 0x0300 {
			return result
		}
	}
	recordLen := binary.BigEndian.Uint16(data[3:5])
	if len(data) < int(5+recordLen) {
		return result
	}
	handshakeData := data[5:]
	if len(handshakeData) < 4 {
		return result
	}
	if handshakeData[0] != 0x01 {
		return result
	}
	handshakeLen := int(handshakeData[1])<<16 | int(handshakeData[2])<<8 | int(handshakeData[3])
	if len(handshakeData) < 4+handshakeLen {
		return result
	}
	clientHello := handshakeData[4:]
	return s.parseClientHello(clientHello)
}

func (s *Sniffer) parseClientHello(data []byte) SniffResult {
	result := SniffResult{Protocol: "tls", Success: false}
	if len(data) < 38 {
		return result
	}
	pos := 2 + 32
	if pos >= len(data) {
		return result
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return result
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherSuitesLen
	if pos >= len(data) {
		return result
	}
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen
	if pos+2 > len(data) {
		return result
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+extensionsLen > len(data) {
		return result
	}
	extensionsData := data[pos : pos+extensionsLen]
	return s.parseExtensions(extensionsData)
}

func (s *Sniffer) parseExtensions(data []byte) SniffResult {
	result := SniffResult{Protocol: "tls", Success: false}
	pos := 0
	for pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos:])
		extLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if pos+extLen > len(data) {
			break
		}
		if extType == 0 {
			sni := s.parseSNI(data[pos : pos+extLen])
			if sni != "" {
				result.Domain = sni
				result.Success = true
				return result
			}
		}
		pos += extLen
	}
	return result
}

func (s *Sniffer) parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:]))
	if listLen+2 > len(data) {
		return ""
	}
	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))
		pos += 3
		if pos+nameLen > len(data) {
			break
		}
		if nameType == 0 {
			hostname := string(data[pos : pos+nameLen])
			if isValidDomain(hostname) {
				return hostname
			}
		}
		pos += nameLen
	}
	return ""
}

func (s *Sniffer) sniffHTTP(data []byte) SniffResult {
	result := SniffResult{Protocol: "http", Success: false}
	if len(data) < 16 {
		return result
	}
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	isHTTP := false
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method)) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return result
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return result
	}
	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if isValidDomain(host) {
			result.Domain = host
			result.Success = true
		}
	}
	return result
}

func (s *Sniffer) sniffQUIC(data []byte) SniffResult {
	result := SniffResult{Protocol: "quic", Success: false}
	if len(data) < 50 {
		return result
	}
	if data[0]&0x80 == 0 {
		return result
	}
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x16 && data[i+1] == 0x03 {
			if tlsResult := s.sniffTLS(data[i:]); tlsResult.Success {
				tlsResult.Protocol = "quic"
				return tlsResult
			}
		}
	}
	return result
}

func isValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func isIPAddress(s string) bool {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	return net.ParseIP(host) != nil
}

// ======================== 原有结构定义 ========================

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
	Type          int
	Value         string
	CompiledRegex *regexp.Regexp
	Node          Node
	Strategy      string
}

type ProxySettings struct {
	Server          string `json:"server"`
	ServerIP        string `json:"server_ip"`
	Token           string `json:"token"`
	Strategy        string `json:"strategy"`
	Rules           string `json:"rules"`
	GlobalKeepAlive bool   `json:"global_keep_alive"`
	S5              string `json:"s5"`

	DNS      *DNSConfig      `json:"dns,omitempty"`
	Sniffing *SniffingConfig `json:"sniffing,omitempty"`

	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
	NodePool          []Node                  `json:"-"`
}

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

type Inbound struct {
	Tag      string          `json:"tag"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Sniffing *SniffingConfig `json:"sniffing,omitempty"`
}

type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type ProxyForwarderSettings struct {
	Socks5Address string
}

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule

	globalDNSResolver *DNSResolver
	globalSniffer     *Sniffer
)

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

func checkFileDependency(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

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
	rawRules := strings.ReplaceAll(s.Rules, "|", "\n")
	lines := strings.Split(rawRules, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			keyword := strings.TrimSpace(parts[0])
			nodeStr := strings.TrimSpace(parts[1])
			strategy := ""
			if len(parts) >= 3 {
				strategy = strings.TrimSpace(parts[2])
			}
			var ruleType int
			var ruleValue string
			var compiledRegex *regexp.Regexp
			if strings.HasPrefix(keyword, "regexp:") {
				ruleType = MatchTypeRegex
				ruleValue = strings.TrimPrefix(keyword, "regexp:")
				compiledRegex = regexp.MustCompile(ruleValue)
			} else if strings.HasPrefix(keyword, "domain:") {
				ruleType = MatchTypeDomain
				ruleValue = strings.TrimPrefix(keyword, "domain:")
			} else if strings.HasPrefix(keyword, "geosite:") {
				ruleType = MatchTypeGeosite
				ruleValue = strings.TrimPrefix(keyword, "geosite:")
			} else if strings.HasPrefix(keyword, "geoip:") {
				ruleType = MatchTypeGeoIP
				ruleValue = strings.TrimPrefix(keyword, "geoip:")
			} else {
				ruleType = MatchTypeSubstring
				ruleValue = keyword
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
				routingMap = append(routingMap, Rule{
					Type:          ruleType,
					Value:         ruleValue,
					CompiledRegex: compiledRegex,
					Node:          foundNode,
					Strategy:      strategy,
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
				if settings.S5 != "" {
					settings.ForwarderSettings = &ProxyForwarderSettings{
						Socks5Address: settings.S5,
					}
				}
				if settings.DNS == nil {
					settings.DNS = &defaultDNSConfig
				}
				if settings.Sniffing == nil {
					settings.Sniffing = &defaultSniffingConfig
				}
				proxySettingsMap[outbound.Tag] = settings
				b, _ := json.Marshal(settings)
				globalConfig.Outbounds[i].Settings = b
			}
		}
	}
}

// ======================== 测速模块 ========================

type TestResult struct {
	Node  Node
	Delay time.Duration
	Error error
}

func pingNode(node Node, token string, globalIP string, results chan<- TestResult) {
	startTime := time.Now()
	backend := selectBackend(node.Backends, "")
	if backend.IP == "" {
		backend.IP = globalIP
	}
	// [v22.0 MODIFIED] pingNode 不需要 Early Data，传空字符串
	conn, err := dialZeusWebSocket(node.Domain, backend, token, "")
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
		if trimmed := strings.TrimSpace(nodeStr); trimmed != "" {
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
	var successful, failed []TestResult
	for res := range results {
		if res.Error == nil {
			successful = append(successful, res)
		} else {
			failed = append(failed, res)
		}
	}
	sort.Slice(successful, func(i, j int) bool { return successful[i].Delay < successful[j].Delay })
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
			if b.Port != "" {
				bStr += ":" + b.Port
			}
			if b.Weight > 1 {
				bStr += "|" + strconv.Itoa(b.Weight)
			}
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

	log.Println("[Core] [依赖检查] 正在检查系统运行环境...")

	hasXray := checkFileDependency("xray.exe")
	if hasXray {
		log.Println("[Core] [依赖检查] ✅ xray.exe 匹配成功! [智能分流] 模式可用。")
	} else {
		log.Println("[Core] [依赖检查] ⚠️ xray.exe 未找到! 如需使用 [智能分流] 模式，请补充此文件。")
	}

	hasGeosite := checkFileDependency("geosite.dat")
	if hasGeosite {
		log.Println("[Core] [依赖检查] ✅ geosite.dat 匹配成功! 已准备好被 [智能分流] 模式调用。")
	} else {
		log.Println("[Core] [依赖检查] ⚠️ geosite.dat 未找到! [智能分流] 的域名规则可能无法生效。")
	}

	hasGeoip := checkFileDependency("geoip.dat")
	if hasGeoip {
		log.Println("[Core] [依赖检查] ✅ geoip.dat 匹配成功! 已准备好被 [智能分流] 模式调用。")
	} else {
		log.Println("[Core] [依赖检查] ⚠️ geoip.dat 未找到! [智能分流] 的 IP 规则可能无法生效。")
	}

	log.Println("[Core] [系统提示] Xlink 内核已就绪。所有复杂路由策略 (Geosite/GeoIP) 将交由 xray.exe 统一处理。")
	log.Println("------------------------------------")

	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, err
	}
	parseOutbounds()

	if s, ok := proxySettingsMap["proxy"]; ok {
		parseRules(s.NodePool)
		if s.DNS != nil {
			globalDNSResolver = NewDNSResolver(*s.DNS)
			log.Printf("[Core] [DNS] 已启用 DNS 解析器 (策略: %s)", s.DNS.Strategy)
		} else {
			globalDNSResolver = NewDNSResolver(defaultDNSConfig)
			log.Printf("[Core] [DNS] 已启用默认 DNS 解析器 (策略: %s)", defaultDNSConfig.Strategy)
		}
		if s.Sniffing != nil {
			globalSniffer = NewSniffer(*s.Sniffing)
			log.Printf("[Core] [Sniffing] 已启用流量嗅探 (协议: %v)", s.Sniffing.DestOverride)
		} else {
			globalSniffer = NewSniffer(defaultSniffingConfig)
			log.Printf("[Core] [Sniffing] 已启用默认流量嗅探 (协议: %v)", defaultSniffingConfig.DestOverride)
		}
	} else {
		globalDNSResolver = NewDNSResolver(defaultDNSConfig)
		globalSniffer = NewSniffer(defaultSniffingConfig)
	}

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds")
	}

	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, err
	}

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

	// [v22.0 MODIFIED] 更新启动日志
	log.Printf("[Core] Xlink Observer Engine (v22.0 CF WAF Evasion) Listening on %s [%s]", inbound.Listen, mode)
	log.Printf("[Core] [Early Data] 已启用协议头抢跑 — 协议头藏入 Sec-WebSocket-Protocol，上行首帧零特征")
	log.Printf("[Core] [IPv6] DNS 策略: %s", globalDNSResolver.config.Strategy)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			go handleGeneralConnection(conn, inbound.Tag)
		}
	}()
	return listener, nil
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
	var pendingData []byte

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

	originalTarget := target
	sniffedDomain := ""

	host, port, _ := net.SplitHostPort(target)
	if isIPAddress(host) && globalSniffer != nil && globalSniffer.config.Enabled {
		if mode == 1 {
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			mode = 0
			sniffBuf := make([]byte, 2048)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, readErr := conn.Read(sniffBuf)
			conn.SetReadDeadline(time.Time{})
			if readErr == nil && n > 0 {
				pendingData = sniffBuf[:n]
				sniffResult := globalSniffer.Sniff(pendingData)
				if sniffResult.Success {
					sniffedDomain = sniffResult.Domain
					log.Printf("[Sniffing] %s -> %s (Protocol: %s)", host, sniffedDomain, sniffResult.Protocol)
				}
			}
		} else if mode == 2 {
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			mode = 0
			sniffBuf := make([]byte, 2048)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, readErr := conn.Read(sniffBuf)
			conn.SetReadDeadline(time.Time{})
			if readErr == nil && n > 0 {
				pendingData = sniffBuf[:n]
				sniffResult := globalSniffer.Sniff(pendingData)
				if sniffResult.Success {
					sniffedDomain = sniffResult.Domain
					log.Printf("[Sniffing] %s -> %s (Protocol: %s)", host, sniffedDomain, sniffResult.Protocol)
				}
			}
		} else if mode == 3 && len(firstFrame) > 0 {
			sniffResult := globalSniffer.Sniff(firstFrame)
			if sniffResult.Success {
				sniffedDomain = sniffResult.Domain
				log.Printf("[Sniffing] %s -> %s (Protocol: %s)", host, sniffedDomain, sniffResult.Protocol)
			}
		}
	}

	finalTarget := target
	if sniffedDomain != "" {
		if globalDNSResolver != nil && globalDNSResolver.config.Enabled {
			resolvedIP, err := globalDNSResolver.ResolveIP(sniffedDomain)
			if err == nil && resolvedIP != sniffedDomain {
				finalTarget = net.JoinHostPort(resolvedIP, port)
				log.Printf("[DNS] %s -> %s", sniffedDomain, resolvedIP)
			} else {
				finalTarget = net.JoinHostPort(sniffedDomain, port)
			}
		} else {
			finalTarget = net.JoinHostPort(sniffedDomain, port)
		}
	} else if !isIPAddress(host) {
		if globalDNSResolver != nil && globalDNSResolver.config.Enabled {
			resolvedIP, err := globalDNSResolver.ResolveIP(host)
			if err == nil && resolvedIP != host {
				finalTarget = net.JoinHostPort(resolvedIP, port)
				log.Printf("[DNS] %s -> %s", host, resolvedIP)
			}
		}
	}

	if finalTarget != originalTarget {
		log.Printf("[Core] Target rewritten: %s -> %s", originalTarget, finalTarget)
	}

	wsConn, err := connectNanoTunnel(finalTarget, "proxy", append(pendingData, firstFrame...))
	if err != nil {
		log.Printf("[Core] Connect failed: %s -> %v", finalTarget, err)
		return
	}

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	pipeDirect(conn, wsConn, finalTarget)
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

// ========================================================================================
// [v22.0 核心改动] connectNanoTunnel — Early Data 抢跑机制
//
// 原 v21.7 流程:  WS握手 → sendNanoHeaderV2(协议头+载荷 作为首个WS二进制帧)
// 新 v22.0 流程:  构建协议头 → Base64URL编码 → 藏入Sec-WebSocket-Protocol HTTP头 → WS握手
//                 上行首帧不再携带任何协议特征，完美绕过 CF WAF 的 DPI 深度包检测
//
// [兼容性] 服务端 22.0 同时支持 Early Data 和传统首帧两种模式:
//   - earlyDataHeader 非空 → 从 HTTP 头解码，注入为流的首帧
//   - earlyDataHeader 为空 → 退化为从首个 WS 消息读取（兼容旧客户端）
// ========================================================================================

func connectNanoTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("settings not found")
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

	// ═══════ [技术1: Early Data] 构建协议头并 Base64URL 编码 ═══════
	headerBytes, err := buildNanoHeader(target, socks5, fallback)
	if err != nil {
		return nil, err
	}

	// 策略：协议头 + 载荷 ≤ 2048字节 → 全部编入 Early Data（一次到位）
	//       超出则仅协议头编入 Early Data，载荷走首个 WS 二进制帧
	const maxEarlyDataSize = 2048
	var earlyDataB64 string
	var remainingPayload []byte

	if len(payload) > 0 && len(headerBytes)+len(payload) <= maxEarlyDataSize {
		// 合并：协议头 + 载荷 → 一次性编入 Early Data
		combined := make([]byte, 0, len(headerBytes)+len(payload))
		combined = append(combined, headerBytes...)
		combined = append(combined, payload...)
		earlyDataB64 = base64.RawURLEncoding.EncodeToString(combined)
		log.Printf("[Early Data] 合并模式: 协议头(%d) + 载荷(%d) = %d bytes → Base64(%d)",
			len(headerBytes), len(payload), len(combined), len(earlyDataB64))
	} else {
		// 分离：仅协议头编入 Early Data
		earlyDataB64 = base64.RawURLEncoding.EncodeToString(headerBytes)
		remainingPayload = payload
		if len(payload) > 0 {
			log.Printf("[Early Data] 分离模式: 协议头(%d) → Base64(%d), 载荷(%d) → 首个WS帧",
				len(headerBytes), len(earlyDataB64), len(payload))
		}
	}

	tryConnectOnce := func() (*websocket.Conn, error) {
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
				return nil, errors.New("no nodes configured in pool")
			}
		}
		log.Print(logMsg)
		backend := selectBackend(targetNode.Backends, target)
		if backend.IP == "" {
			backend.IP = settings.ServerIP
		}
		start := time.Now()

		// [v22.0 MODIFIED] 传入 earlyDataB64，协议头藏入 HTTP 升级头
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey, earlyDataB64)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return nil, err
		}
		if backend.IP != "" {
			log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real) | Latency: %dms", targetNode.Domain, backend.IP, backend.Port, latency)
		}

		// [v22.0 NEW] 仅当载荷未编入 Early Data 时，作为首个 WS 帧发送
		if len(remainingPayload) > 0 {
			if err := wsConn.WriteMessage(websocket.BinaryMessage, remainingPayload); err != nil {
				wsConn.Close()
				return nil, err
			}
		}

		return wsConn, nil
	}

	conn, err := tryConnectOnce()
	if err != nil && len(settings.NodePool) > 1 {
		log.Printf("[Core] Connect failed: %v. Retry...", err)
		return tryConnectOnce()
	}
	return conn, err
}

func selectBackend(backends []Backend, key string) Backend {
	if len(backends) == 0 {
		return Backend{}
	}
	if len(backends) == 1 {
		return backends[0]
	}
	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.Weight
	}
	h := md5.Sum([]byte(key))
	hashVal := binary.BigEndian.Uint64(h[:8])
	if totalWeight == 0 {
		return backends[int(hashVal%uint64(len(backends)))]
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

// ========================================================================================
// [v22.0 MODIFIED] dialZeusWebSocket — 新增 earlyData 参数
//
// 当 earlyData 非空时，将其设置为 Sec-WebSocket-Protocol 请求头。
// 服务端从该头部提取 Base64 编码的协议数据，注入为可读流的首帧。
// 效果：WS 握手阶段即完成协议协商，上行首个 WS 数据帧完全是业务载荷，无任何协议指纹。
// ========================================================================================

func dialZeusWebSocket(sni string, backend Backend, token string, earlyData string) (*websocket.Conn, error) {
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

	// [v22.0 NEW] ═══════ Early Data: 协议头藏入 Sec-WebSocket-Protocol ═══════
	// 使用直接赋值 requestHeader["Sec-WebSocket-Protocol"] 而非 Dialer.Subprotocols，
	// 避免 gorilla/websocket 对响应头的子协议验证逻辑，提高鲁棒性。
	if earlyData != "" {
		requestHeader["Sec-WebSocket-Protocol"] = []string{earlyData}
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
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

func pipeDirect(local net.Conn, ws *websocket.Conn, target string) {
	defer ws.Close()
	defer local.Close()
	var upBytes, downBytes int64
	startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			mt, r, err := ws.NextReader()
			if err != nil {
				break
			}
			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				if err == nil {
					atomic.AddInt64(&downBytes, n)
				}
				if err != nil {
					break
				}
			}
		}
		local.Close()
	}()
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				atomic.AddInt64(&upBytes, int64(n))
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()
	wg.Wait()
	duration := time.Since(startTime)
	log.Printf("[Stats] %s | Up: %s | Down: %s | Time: %v", target, formatBytes(upBytes), formatBytes(downBytes), duration.Round(time.Second))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ========================================================================================
// [v22.0 NEW] buildNanoHeader — 构建二进制协议头（不含载荷）
//
// 协议头格式: [HostLen(1)][Host(var)][Port(2)][S5Len(1)][S5(var)][FBLen(1)][FB(var)]
// 该字节序列经 Base64URL 编码后，藏入 Sec-WebSocket-Protocol HTTP 头，
// 使得 WebSocket 建立后的首个数据帧不再携带任何自定义协议特征。
// ========================================================================================

func buildNanoHeader(target string, s5 string, fb string) ([]byte, error) {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// 处理 IPv6 地址格式
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = ip.String()
	}

	hostBytes, s5Bytes, fbBytes := []byte(host), []byte(s5), []byte(fb)
	if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 {
		return nil, errors.New("address length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	buf.Write(portBuf)
	buf.WriteByte(byte(len(s5Bytes)))
	if len(s5Bytes) > 0 {
		buf.Write(s5Bytes)
	}
	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}
	return buf.Bytes(), nil
}

// [v22.0 DEPRECATED] sendNanoHeaderV2 — 旧版协议头发送（保留用于向后兼容参考）
// 新版通过 Early Data 机制将协议头藏入 HTTP 升级头，不再需要此函数。
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = ip.String()
	}
	hostBytes, s5Bytes, fbBytes := []byte(host), []byte(s5), []byte(fb)
	if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 {
		return errors.New("address length exceeds 255 bytes")
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf.Write(portBytes)
	buf.WriteByte(byte(len(s5Bytes)))
	if len(s5Bytes) > 0 {
		buf.Write(s5Bytes)
	}
	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}
	if len(payload) > 0 {
		buf.Write(payload)
	}
	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2)
	io.ReadFull(conn, handshakeBuf)
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4)
	io.ReadFull(conn, header)
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
	}
	portBytes := make([]byte, 2)
	io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", nil, 0, err
	}
	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" {
			target += ":443"
		} else {
			target += ":80"
		}
	}
	if req.Method == "CONNECT" {
		return target, nil, 2, nil
	}
	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}
