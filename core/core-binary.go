// =========================================================================================
// Xlink Core v21.6 (IPv6 Enhanced Kernel)
// [新增] 完整 DNS 解析能力 (DoH, IPv4/IPv6 双栈)
// [新增] TLS/HTTP Sniffing 功能 (恢复原始域名)
// [优化] 入站协议完整支持 IPv6 数据包封装
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
	DNSStrategyUseIP       DNSStrategy = "UseIP"       // 同时查询 A 和 AAAA，返回所有
	DNSStrategyUseIPv4     DNSStrategy = "UseIPv4"     // 只查询 A 记录
	DNSStrategyUseIPv6     DNSStrategy = "UseIPv6"     // 只查询 AAAA 记录
	DNSStrategyPreferIPv6  DNSStrategy = "PreferIPv6"  // 优先返回 IPv6
	DNSStrategyPreferIPv4  DNSStrategy = "PreferIPv4"  // 优先返回 IPv4
)

// DNSConfig DNS 配置
type DNSConfig struct {
	Enabled       bool        `json:"enabled"`
	Strategy      DNSStrategy `json:"strategy"`
	Servers       []string    `json:"servers"`        // DoH 服务器列表
	FallbackDNS   []string    `json:"fallback_dns"`   // 备用 DNS
	CacheTTL      int         `json:"cache_ttl"`      // 缓存时间（秒）
	TimeoutMs     int         `json:"timeout_ms"`     // 超时时间
}

// SniffingConfig 流量嗅探配置
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"dest_override"` // ["http", "tls", "quic"]
	RouteOnly    bool     `json:"route_only"`    // 仅用于路由，不重写目标
}

// 默认配置
var defaultDNSConfig = DNSConfig{
	Enabled:  true,
	Strategy: DNSStrategyPreferIPv6,
	Servers: []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
	},
	FallbackDNS: []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"[2606:4700:4700::1111]:53",
		"[2001:4860:4860::8888]:53",
	},
	CacheTTL:  300,
	TimeoutMs: 3000,
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

// DNSResolver DNS 解析器
type DNSResolver struct {
	config     DNSConfig
	httpClient *http.Client
}

// NewDNSResolver 创建 DNS 解析器
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

// ResolveIP 解析域名，根据策略返回 IP
func (r *DNSResolver) ResolveIP(domain string) (string, error) {
	if !r.config.Enabled {
		return domain, nil // 不启用 DNS 解析，直接返回域名
	}

	// 如果已经是 IP 地址，直接返回
	if ip := net.ParseIP(domain); ip != nil {
		return domain, nil
	}

	// 检查缓存
	if cached := r.getFromCache(domain); cached != "" {
		log.Printf("[DNS] Cache hit: %s -> %s", domain, cached)
		return cached, nil
	}

	// 执行 DNS 解析
	ipv4s, ipv6s, err := r.resolveAll(domain)
	if err != nil {
		log.Printf("[DNS] Resolve failed for %s: %v", domain, err)
		return domain, err // 失败时返回原域名，让远程服务器解析
	}

	// 缓存结果
	r.saveToCache(domain, ipv4s, ipv6s)

	// 根据策略选择 IP
	result := r.selectIP(ipv4s, ipv6s)
	if result == "" {
		return domain, nil // 无结果时返回原域名
	}

	log.Printf("[DNS] Resolved: %s -> %s (Strategy: %s)", domain, result, r.config.Strategy)
	return result, nil
}

// ResolveToIPv6 尝试解析为 IPv6，失败则返回原值
func (r *DNSResolver) ResolveToIPv6(domain string) (string, bool) {
	if !r.config.Enabled {
		return domain, false
	}

	if ip := net.ParseIP(domain); ip != nil {
		return domain, ip.To4() == nil // 已经是 IP，返回是否为 IPv6
	}

	// 检查缓存
	dnsCache.RLock()
	if entry, ok := dnsCache.entries[domain]; ok && time.Now().Before(entry.expires) {
		if len(entry.ipv6) > 0 {
			dnsCache.RUnlock()
			return entry.ipv6[0].String(), true
		}
	}
	dnsCache.RUnlock()

	// 解析
	_, ipv6s, err := r.resolveAll(domain)
	if err != nil || len(ipv6s) == 0 {
		return domain, false
	}

	return ipv6s[0].String(), true
}

// resolveAll 同时解析 IPv4 和 IPv6
func (r *DNSResolver) resolveAll(domain string) ([]net.IP, []net.IP, error) {
	var ipv4s, ipv6s []net.IP
	var lastErr error

	// 尝试 DoH 服务器
	for _, server := range r.config.Servers {
		v4, v6, err := r.resolveDoH(server, domain)
		if err == nil {
			ipv4s = append(ipv4s, v4...)
			ipv6s = append(ipv6s, v6...)
			if len(ipv4s) > 0 || len(ipv6s) > 0 {
				return ipv4s, ipv6s, nil
			}
		}
		lastErr = err
	}

	// DoH 失败，使用系统 DNS
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

	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, err
}

// resolveDoH 使用 DoH 解析
func (r *DNSResolver) resolveDoH(server, domain string) ([]net.IP, []net.IP, error) {
	var ipv4s, ipv6s []net.IP
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 根据策略决定查询类型
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

// doHQuery 执行单个 DoH 查询
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
		// Type 1 = A, Type 28 = AAAA
		if (recordType == "A" && ans.Type == 1) || (recordType == "AAAA" && ans.Type == 28) {
			if ip := net.ParseIP(ans.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

// resolveSystem 使用系统 DNS 解析
func (r *DNSResolver) resolveSystem(domain string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TimeoutMs)*time.Millisecond)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// selectIP 根据策略选择 IP
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
	default: // UseIP
		// 随机选择一个
		all := append(ipv6s, ipv4s...)
		if len(all) > 0 {
			return all[rand.Intn(len(all))].String()
		}
	}
	return ""
}

// getFromCache 从缓存获取
func (r *DNSResolver) getFromCache(domain string) string {
	dnsCache.RLock()
	defer dnsCache.RUnlock()

	entry, ok := dnsCache.entries[domain]
	if !ok || time.Now().After(entry.expires) {
		return ""
	}

	return r.selectIP(entry.ipv4, entry.ipv6)
}

// saveToCache 保存到缓存
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

// SniffResult 嗅探结果
type SniffResult struct {
	Domain   string
	Protocol string // "tls", "http", "quic"
	Success  bool
}

// Sniffer 流量嗅探器
type Sniffer struct {
	config SniffingConfig
}

// NewSniffer 创建嗅探器
func NewSniffer(config SniffingConfig) *Sniffer {
	return &Sniffer{config: config}
}

// Sniff 嗅探流量，尝试提取域名
func (s *Sniffer) Sniff(data []byte) SniffResult {
	if !s.config.Enabled || len(data) == 0 {
		return SniffResult{Success: false}
	}

	// 尝试 TLS 嗅探
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

// sniffTLS 嗅探 TLS ClientHello，提取 SNI
func (s *Sniffer) sniffTLS(data []byte) SniffResult {
	result := SniffResult{Protocol: "tls", Success: false}

	if len(data) < 5 {
		return result
	}

	// TLS Record Header: ContentType(1) + Version(2) + Length(2)
	// ContentType 22 = Handshake
	if data[0] != 0x16 {
		return result
	}

	// 检查版本 (TLS 1.0, 1.1, 1.2, 1.3)
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0301 || version > 0x0304 {
		// 也接受 0x0300 (SSL 3.0) 的 ClientHello
		if version != 0x0300 {
			return result
		}
	}

	recordLen := binary.BigEndian.Uint16(data[3:5])
	if len(data) < int(5+recordLen) {
		return result
	}

	// Handshake Header: HandshakeType(1) + Length(3)
	handshakeData := data[5:]
	if len(handshakeData) < 4 {
		return result
	}

	// HandshakeType 1 = ClientHello
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

// parseClientHello 解析 ClientHello，提取 SNI
func (s *Sniffer) parseClientHello(data []byte) SniffResult {
	result := SniffResult{Protocol: "tls", Success: false}

	if len(data) < 38 {
		return result
	}

	// ClientHello 结构:
	// Version(2) + Random(32) + SessionIDLen(1) + SessionID(var) + ...

	pos := 2 + 32 // Skip version and random

	// Session ID
	if pos >= len(data) {
		return result
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+2 > len(data) {
		return result
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherSuitesLen

	// Compression Methods
	if pos >= len(data) {
		return result
	}
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen

	// Extensions
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

// parseExtensions 解析扩展，找到 SNI
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

		// Extension Type 0 = SNI
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

// parseSNI 解析 SNI 扩展
func (s *Sniffer) parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI List Length(2) + SNI Type(1) + SNI Length(2) + SNI
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

		// Name Type 0 = hostname
		if nameType == 0 {
			hostname := string(data[pos : pos+nameLen])
			// 验证是有效域名
			if isValidDomain(hostname) {
				return hostname
			}
		}

		pos += nameLen
	}

	return ""
}

// sniffHTTP 嗅探 HTTP 请求，提取 Host
func (s *Sniffer) sniffHTTP(data []byte) SniffResult {
	result := SniffResult{Protocol: "http", Success: false}

	// 检查是否是 HTTP 请求
	if len(data) < 16 {
		return result
	}

	// 常见 HTTP 方法
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

	// 解析 HTTP 请求
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
		// 移除端口
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

// sniffQUIC 嗅探 QUIC 初始包 (简化实现)
func (s *Sniffer) sniffQUIC(data []byte) SniffResult {
	result := SniffResult{Protocol: "quic", Success: false}

	// QUIC Initial Packet 结构较复杂，这里做简化处理
	// 完整实现需要解析 QUIC 帧格式

	if len(data) < 50 {
		return result
	}

	// 检查是否是 QUIC Long Header
	if data[0]&0x80 == 0 {
		return result
	}

	// QUIC 版本
	// version := binary.BigEndian.Uint32(data[1:5])

	// 尝试在数据中搜索 TLS ClientHello (QUIC 加密层内)
	// 这是一个简化的启发式方法
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

// isValidDomain 检查是否是有效域名
func isValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}

	// 不是 IP 地址
	if net.ParseIP(s) != nil {
		return false
	}

	// 基本域名格式检查
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		// 简单检查：只包含字母、数字、连字符
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}

	return true
}

// isIPAddress 检查是否是 IP 地址
func isIPAddress(s string) bool {
	// 处理带端口的情况
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

// [v21.6] ProxySettings 结构体 - 新增 DNS 和 Sniffing 配置
type ProxySettings struct {
	Server          string `json:"server"`
	ServerIP        string `json:"server_ip"`
	Token           string `json:"token"`
	Strategy        string `json:"strategy"`
	Rules           string `json:"rules"`
	GlobalKeepAlive bool   `json:"global_keep_alive"`
	S5              string `json:"s5"`

	// [v21.6 新增] DNS 配置
	DNS *DNSConfig `json:"dns,omitempty"`
	
	// [v21.6 新增] Sniffing 配置
	Sniffing *SniffingConfig `json:"sniffing,omitempty"`

	// 内部使用的字段
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
	Sniffing *SniffingConfig `json:"sniffing,omitempty"` // [v21.6 新增]
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
	
	// [v21.6 新增] 全局 DNS 解析器和嗅探器
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

				// [v21.6 新增] 初始化 DNS 配置
				if settings.DNS == nil {
					settings.DNS = &defaultDNSConfig
				}
				
				// [v21.6 新增] 初始化 Sniffing 配置
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
	
	// [v21.6 新增] 初始化全局 DNS 解析器和嗅探器
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
	
	// [v21.6] 更新启动日志
	log.Printf("[Core] Xlink Observer Engine (v21.6 IPv6 Enhanced) Listening on %s [%s]", inbound.Listen, mode)
	log.Printf("[Core] [IPv6] 已启用 IPv6 优先模式，DNS 策略: %s", globalDNSResolver.config.Strategy)
	
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

// [v21.6 重写] handleGeneralConnection - 添加 Sniffing 和 DNS 解析
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
	var pendingData []byte // [v21.6] 用于 Sniffing 的待读取数据
	
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

	// [v21.6 新增] Sniffing 处理流程
	originalTarget := target
	sniffedDomain := ""
	
	// 检查目标是否是 IP 地址（如果是域名则不需要 Sniffing）
	host, port, _ := net.SplitHostPort(target)
	if isIPAddress(host) && globalSniffer != nil && globalSniffer.config.Enabled {
		// 目标是 IP 地址，需要 Sniffing 来恢复域名
		
		if mode == 1 {
			// SOCKS5 模式：先发送成功响应，然后读取实际数据进行 Sniffing
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			mode = 0 // 标记已发送响应
			
			// 读取一些数据用于 Sniffing
			sniffBuf := make([]byte, 2048)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, readErr := conn.Read(sniffBuf)
			conn.SetReadDeadline(time.Time{}) // 清除超时
			
			if readErr == nil && n > 0 {
				pendingData = sniffBuf[:n]
				sniffResult := globalSniffer.Sniff(pendingData)
				if sniffResult.Success {
					sniffedDomain = sniffResult.Domain
					log.Printf("[Sniffing] %s -> %s (Protocol: %s)", host, sniffedDomain, sniffResult.Protocol)
				}
			}
		} else if mode == 2 {
			// HTTPS CONNECT 模式：先发送成功响应，然后读取 TLS ClientHello
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			mode = 0 // 标记已发送响应
			
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
			// HTTP 明文模式：从已有的 firstFrame 中 Sniff
			sniffResult := globalSniffer.Sniff(firstFrame)
			if sniffResult.Success {
				sniffedDomain = sniffResult.Domain
				log.Printf("[Sniffing] %s -> %s (Protocol: %s)", host, sniffedDomain, sniffResult.Protocol)
			}
		}
	}

	// [v21.6 新增] DNS 解析处理
	finalTarget := target
	if sniffedDomain != "" {
		// Sniffing 成功，使用域名进行 DNS 解析
		if globalDNSResolver != nil && globalDNSResolver.config.Enabled {
			resolvedIP, err := globalDNSResolver.ResolveIP(sniffedDomain)
			if err == nil && resolvedIP != sniffedDomain {
				// 使用解析后的 IP (可能是 IPv6)
				finalTarget = net.JoinHostPort(resolvedIP, port)
				log.Printf("[DNS] %s -> %s", sniffedDomain, resolvedIP)
			} else {
				// DNS 解析失败或返回域名本身，使用原始域名
				finalTarget = net.JoinHostPort(sniffedDomain, port)
			}
		} else {
			// DNS 未启用，直接使用域名
			finalTarget = net.JoinHostPort(sniffedDomain, port)
		}
	} else if !isIPAddress(host) {
		// 目标本身就是域名，进行 DNS 解析
		if globalDNSResolver != nil && globalDNSResolver.config.Enabled {
			resolvedIP, err := globalDNSResolver.ResolveIP(host)
			if err == nil && resolvedIP != host {
				finalTarget = net.JoinHostPort(resolvedIP, port)
				log.Printf("[DNS] %s -> %s", host, resolvedIP)
			}
		}
	}

	// 如果目标发生变化，记录日志
	if finalTarget != originalTarget {
		log.Printf("[Core] Target rewritten: %s -> %s", originalTarget, finalTarget)
	}

	// 建立到远程的连接
	wsConn, err := connectNanoTunnel(finalTarget, "proxy", append(pendingData, firstFrame...))
	if err != nil {
		log.Printf("[Core] Connect failed: %s -> %v", finalTarget, err)
		return
	}
	
	// 根据 mode 发送适当的响应（如果还没发送的话）
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
		wsConn, err := dialZeusWebSocket(targetNode.Domain, backend, secretKey)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return nil, err
		}
		if backend.IP != "" {
			log.Printf("[Core] Tunnel -> %s (SNI) >>> %s:%s (Real) | Latency: %dms", targetNode.Domain, backend.IP, backend.Port, latency)
		}
		err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
		if err != nil {
			wsConn.Close()
			return nil, err
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

func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	
	// [v21.6] 处理 IPv6 地址格式
	// 如果 host 是 IPv6 地址，确保格式正确
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// 是 IPv6 地址，保持原样（不加方括号，因为这是原始传输）
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
	case 1: // IPv4
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 3: // Domain
		b := make([]byte, 1)
		io.ReadFull(conn, b)
		d := make([]byte, b[0])
		io.ReadFull(conn, d)
		host = string(d)
	case 4: // IPv6
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
