
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

const (
	connTimeoutProxy    = 3 * time.Second
	connTimeoutDirect   = 4 * time.Second
	connTimeoutFallback = 5 * time.Second

	sniffReadTimeout    = 500 * time.Millisecond
	wsHandshakeTimeout  = 5 * time.Second
	idleConnTimeout     = 30 * time.Second
	tlsHandshakeTimeout = 5 * time.Second

	socks5Version byte = 0x05
)

var globalRRIndex uint64

type connMode int

const (
	modeResponded     connMode = 0
	modeSOCKS5Pending connMode = 1
	modeHTTPSPending  connMode = 2
	modeHTTPPlain     connMode = 3
)

type TunnelError struct {
	Stage string
	Err   error
}

func (e *TunnelError) Error() string {
	return fmt.Sprintf("%s: %v", e.Stage, e.Err)
}

type SafeWS struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	readMu  sync.Mutex
}

type lockedReader struct {
	io.Reader
	unlock func()
	once   sync.Once
}

func (r *lockedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.once.Do(r.unlock)
	}
	return n, err
}

func (s *SafeWS) NextReader() (int, io.Reader, error) {
	s.readMu.Lock()
	mt, r, err := s.conn.NextReader()
	if err != nil {
		s.readMu.Unlock()
		return mt, r, err
	}
	return mt, &lockedReader{
		Reader: r,
		unlock: s.readMu.Unlock,
	}, nil
}

func (s *SafeWS) WriteMessage(mt int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteMessage(mt, data)
}

func (s *SafeWS) Close() error {
	return s.conn.Close()
}

type DNSStrategy string

const (
	DNSStrategyUseIP      DNSStrategy = "UseIP"
	DNSStrategyUseIPv4    DNSStrategy = "UseIPv4"
	DNSStrategyUseIPv6    DNSStrategy = "UseIPv6"
	DNSStrategyPreferIPv6 DNSStrategy = "PreferIPv6"
	DNSStrategyPreferIPv4 DNSStrategy = "PreferIPv4"
)

type DNSConfig struct {
	Enabled          bool        `json:"enabled"`
	Strategy         DNSStrategy `json:"strategy"`
	Servers          []string    `json:"servers"`
	FallbackToRemote bool        `json:"fallback_to_remote"`
	CacheTTL         int         `json:"cache_ttl"`
	TimeoutMs        int         `json:"timeout_ms"`
}

type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"dest_override"`
	RouteOnly    bool     `json:"route_only"`
}

var defaultDNSConfig = DNSConfig{
	Enabled:          true,
	Strategy:         DNSStrategyPreferIPv4,
	Servers:          []string{"https://223.5.5.5/dns-query", "https://dns.google/dns-query"},
	FallbackToRemote: true,
	CacheTTL:         600,
	TimeoutMs:        800,
}

var defaultSniffingConfig = SniffingConfig{
	Enabled:      true,
	DestOverride: []string{"http", "tls"},
	RouteOnly:    false,
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
}

type dnsCacheEntry struct {
	ipv4    []net.IP
	ipv6    []net.IP
	expires time.Time
}

var globalDNSCache = &dnsCache{entries: make(map[string]*dnsCacheEntry)}

func (c *dnsCache) get(domain string) (ipv4, ipv6 []net.IP, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, exists := c.entries[domain]
	if !exists || time.Now().After(entry.expires) {
		return nil, nil, false
	}
	return entry.ipv4, entry.ipv6, true
}

func (c *dnsCache) set(domain string, ipv4, ipv6 []net.IP, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[domain] = &dnsCacheEntry{
		ipv4:    ipv4,
		ipv6:    ipv6,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (c *dnsCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.entries {
		if now.After(v.expires) {
			delete(c.entries, k)
		}
	}
}

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
		MaxIdleConnsPerHost: 2,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     idleConnTimeout,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
	}
	return &DNSResolver{
		config: config,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
		},
	}
}

func (r *DNSResolver) ResolveIP(domain string) string {
	if !r.config.Enabled {
		return domain
	}
	if net.ParseIP(domain) != nil {
		return domain
	}

	if ipv4s, ipv6s, ok := globalDNSCache.get(domain); ok {
		if result := r.selectIP(ipv4s, ipv6s); result != "" {
			log.Printf("[DNS] cache:%s→%s", domain, result)
			return result
		}
	}

	ipv4s, ipv6s, err := r.resolveAll(domain)
	if err != nil || (len(ipv4s) == 0 && len(ipv6s) == 0) {
		log.Printf("[DNS] resolve failed:%s err:%v fallback to domain", domain, err)
		return domain
	}

	globalDNSCache.set(domain, ipv4s, ipv6s, r.config.CacheTTL)

	result := r.selectIP(ipv4s, ipv6s)
	if result == "" {
		return domain
	}
	log.Printf("[DNS] resolved:%s→%s strategy:%s", domain, result, r.config.Strategy)
	return result
}

func (r *DNSResolver) resolveAll(domain string) ([]net.IP, []net.IP, error) {
	for _, server := range r.config.Servers {
		v4, v6, err := r.resolveDoH(server, domain)
		if err == nil && (len(v4) > 0 || len(v6) > 0) {
			return v4, v6, nil
		}
	}
	if r.config.FallbackToRemote {
		return r.resolveSystem(domain)
	}
	return nil, nil, errors.New("all DoH servers failed, fallback disabled")
}

func (r *DNSResolver) resolveDoH(server, domain string) ([]net.IP, []net.IP, error) {
	var ipv4s, ipv6s []net.IP
	var mu sync.Mutex
	var wg sync.WaitGroup

	queryA    := r.config.Strategy != DNSStrategyUseIPv6
	queryAAAA := r.config.Strategy != DNSStrategyUseIPv4

	if queryA {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ips, err := r.doHQuery(server, domain, "A"); err == nil {
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
			if ips, err := r.doHQuery(server, domain, "AAAA"); err == nil {
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
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
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

func (r *DNSResolver) resolveSystem(domain string) ([]net.IP, []net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TimeoutMs)*time.Millisecond)
	defer cancel()

	all, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, nil, err
	}

	var ipv4s, ipv6s []net.IP
	for _, ip := range all {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}
	return ipv4s, ipv6s, nil
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
		return SniffResult{}
	}
	for _, proto := range s.config.DestOverride {
		switch proto {
		case "tls":
			if r := s.sniffTLS(data); r.Success {
				return r
			}
		case "http":
			if r := s.sniffHTTP(data); r.Success {
				return r
			}
		}
	}
	return SniffResult{}
}

func (s *Sniffer) sniffTLS(data []byte) SniffResult {
	if len(data) < 5 || data[0] != 0x16 {
		return SniffResult{}
	}

	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0300 || version > 0x0304 {
		return SniffResult{}
	}

	recordLen := binary.BigEndian.Uint16(data[3:5])
	if len(data) < int(5+recordLen) {
		return SniffResult{}
	}

	handshakeData := data[5:]
	if len(handshakeData) < 4 || handshakeData[0] != 0x01 {
		return SniffResult{}
	}

	handshakeLen := int(handshakeData[1])<<16 | int(handshakeData[2])<<8 | int(handshakeData[3])
	if len(handshakeData) < 4+handshakeLen {
		return SniffResult{}
	}

	return s.parseClientHello(handshakeData[4:])
}

func (s *Sniffer) parseClientHello(data []byte) SniffResult {
	if len(data) < 38 {
		return SniffResult{}
	}

	pos := 34
	if pos >= len(data) {
		return SniffResult{}
	}

	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return SniffResult{}
	}

	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen
	if pos >= len(data) {
		return SniffResult{}
	}

	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > len(data) {
		return SniffResult{}
	}

	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+extLen > len(data) {
		return SniffResult{}
	}

	return s.parseExtensions(data[pos : pos+extLen])
}

func (s *Sniffer) parseExtensions(data []byte) SniffResult {
	for pos := 0; pos+4 <= len(data); {
		extType := binary.BigEndian.Uint16(data[pos:])
		extLen  := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if pos+extLen > len(data) {
			break
		}
		if extType == 0 {
			if domain := s.parseSNI(data[pos : pos+extLen]); domain != "" {
				return SniffResult{Domain: domain, Protocol: "tls", Success: true}
			}
		}
		pos += extLen
	}
	return SniffResult{}
}

func (s *Sniffer) parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:]))
	if listLen+2 > len(data) {
		return ""
	}

	for pos := 2; pos+3 <= 2+listLen; {
		nameType := data[pos]
		nameLen  := int(binary.BigEndian.Uint16(data[pos+1:]))
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
	if len(data) < 16 {
		return SniffResult{}
	}

	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	isHTTP := false
	for _, m := range methods {
		if bytes.HasPrefix(data, []byte(m)) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return SniffResult{}
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return SniffResult{}
	}

	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host == "" {
		return SniffResult{}
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !isValidDomain(host) {
		return SniffResult{}
	}

	return SniffResult{Domain: host, Protocol: "http", Success: true}
}

func isValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
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
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-') {
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
	globalConfig      Config
	proxySettingsMap  = make(map[string]ProxySettings)
	routingMap        []Rule
	globalDNSResolver *DNSResolver
	globalSniffer     *Sniffer

	maintenanceStopCh chan struct{}
)

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

func parseNode(nodeStr string) Node {
	var n Node
	parts := strings.SplitN(nodeStr, "#", 2)
	n.Domain = strings.TrimSpace(parts[0])
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		// 没有 # 分隔符，或 # 后为空：域名本身作为唯一 Backend
		// 端口留空，由 dialZeusWebSocket 从 SNI 端口继承（默认443）
		n.Backends = append(n.Backends, Backend{IP: n.Domain, Port: "", Weight: 1})
		return n
	}

	for _, e := range strings.Split(strings.TrimSpace(parts[1]), ",") {
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
	if err := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err != nil || s.Rules == "" {
		return
	}

	rawRules := strings.NewReplacer("|", "\n", "，", ",").Replace(s.Rules)
	for _, line := range strings.Split(rawRules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		keyword  := strings.TrimSpace(parts[0])
		nodeStr  := strings.TrimSpace(parts[1])
		strategy := ""
		if len(parts) >= 3 {
			strategy = strings.TrimSpace(parts[2])
		}

		var ruleType int
		var ruleValue string
		var compiledRegex *regexp.Regexp

		switch {
		case strings.HasPrefix(keyword, "regexp:"):
			ruleType = MatchTypeRegex
			ruleValue = strings.TrimPrefix(keyword, "regexp:")
			compiledRegex = regexp.MustCompile(ruleValue)
		case strings.HasPrefix(keyword, "domain:"):
			ruleType = MatchTypeDomain
			ruleValue = strings.TrimPrefix(keyword, "domain:")
		case strings.HasPrefix(keyword, "geosite:"):
			ruleType = MatchTypeGeosite
			ruleValue = strings.TrimPrefix(keyword, "geosite:")
		case strings.HasPrefix(keyword, "geoip:"):
			ruleType = MatchTypeGeoIP
			ruleValue = strings.TrimPrefix(keyword, "geoip:")
		default:
			ruleType = MatchTypeSubstring
			ruleValue = keyword
		}

		var foundNode Node
		for _, pNode := range pool {
			if pNode.Domain == nodeStr {
				foundNode = pNode
				break
			}
		}
		if foundNode.Domain == "" {
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

func parseOutbounds() {
	for i, outbound := range globalConfig.Outbounds {
		if outbound.Protocol != "ech-proxy" {
			continue
		}

		var settings ProxySettings
		if err := json.Unmarshal(outbound.Settings, &settings); err != nil {
			continue
		}

		// 统一所有分隔符为换行符，再按行切分
		// 客户端通过 EscapeJson 将 \n 转义写入JSON，Go解析JSON后还原为真正换行符
		rawPool := strings.NewReplacer(
			"\r\n", "\n",
			";", "\n",
			"；", "\n",
			"，", "\n",
		).Replace(settings.Server)
		for _, nodeStr := range strings.Split(rawPool, "\n") {
			if trimmed := strings.TrimSpace(nodeStr); trimmed != "" {
				settings.NodePool = append(settings.NodePool, parseNode(trimmed))
			}
		}

		if settings.S5 != "" {
			settings.ForwarderSettings = &ProxyForwarderSettings{Socks5Address: settings.S5}
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

type TestResult struct {
	Node  Node
	Delay time.Duration
	Error error
}

func pingNode(node Node, token, globalIP string, results chan<- TestResult) {
	start := time.Now()
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
	results <- TestResult{Node: node, Delay: time.Since(start)}
}

func RunSpeedTest(serverAddr, token, globalIP string) {
	rawPool := strings.NewReplacer("\r\n", ";", "\n", ";").Replace(serverAddr)
	var nodes []Node
	for _, s := range strings.Split(rawPool, ";") {
		if t := strings.TrimSpace(s); t != "" {
			nodes = append(nodes, parseNode(t))
		}
	}
	if len(nodes) == 0 {
		log.Println("No valid nodes found.")
		return
	}

	var wg sync.WaitGroup
	results := make(chan TestResult, len(nodes))
	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			pingNode(n, strings.SplitN(token, "|", 2)[0], globalIP, results)
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
}

func formatNode(n Node) string {
	if len(n.Backends) == 0 {
		return n.Domain
	}
	var sb strings.Builder
	sb.WriteString(n.Domain)
	sb.WriteByte('#')
	for i, b := range n.Backends {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(b.IP)
		if b.Port != "" {
			sb.WriteByte(':')
			sb.WriteString(b.Port)
		}
		if b.Weight > 1 {
			sb.WriteByte('|')
			sb.WriteString(strconv.Itoa(b.Weight))
		}
	}
	return sb.String()
}

func checkFileDependency(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func StartInstance(configContent []byte) (net.Listener, error) {
	if maintenanceStopCh != nil {
		close(maintenanceStopCh)
		maintenanceStopCh = nil
	}

	proxySettingsMap = make(map[string]ProxySettings)
	routingMap = nil

	log.Println("[Core] 正在检查运行环境...")
	for _, dep := range []string{"xray.exe", "geosite.dat", "geoip.dat"} {
		if checkFileDependency(dep) {
			log.Printf("[Core] ✅ %s", dep)
		} else {
			log.Printf("[Core] ⚠️  %s 未找到", dep)
		}
	}

	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, err
	}
	parseOutbounds()

	s, hasProxy := proxySettingsMap["proxy"]
	if hasProxy {
		parseRules(s.NodePool)
		dnsConfig := defaultDNSConfig
		if s.DNS != nil {
			dnsConfig = *s.DNS
		}
		globalDNSResolver = NewDNSResolver(dnsConfig)
		log.Printf("[Core] [DNS] strategy:%s", dnsConfig.Strategy)

		sniffConfig := defaultSniffingConfig
		if s.Sniffing != nil {
			sniffConfig = *s.Sniffing
		}
		globalSniffer = NewSniffer(sniffConfig)
		log.Printf("[Core] [Sniff] protocols:%v", sniffConfig.DestOverride)
	} else {
		globalDNSResolver = NewDNSResolver(defaultDNSConfig)
		globalSniffer = NewSniffer(defaultSniffingConfig)
	}

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}

	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, err
	}

	mode := "Single Node"
	if hasProxy {
		if len(s.NodePool) > 1 {
			mode = fmt.Sprintf("Pool(%d nodes, strategy:%s)", len(s.NodePool), s.Strategy)
		} else if len(s.NodePool) == 1 {
			mode = fmt.Sprintf("Single(%s)", s.NodePool[0].Domain)
		}
		if len(routingMap) > 0 {
			mode += fmt.Sprintf("+%dRules", len(routingMap))
		}
	}
	log.Printf("[Core] v21.8 listening:%s mode:%s", inbound.Listen, mode)

	maintenanceStopCh = make(chan struct{})

	go func(stopCh <-chan struct{}) {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				globalDNSCache.cleanup()
			case <-stopCh:
				return
			}
		}
	}(maintenanceStopCh)

	go acceptLoop(listener, inbound.Tag)
	return listener, nil
}

func StopInstance(listener net.Listener) {
	if maintenanceStopCh != nil {
		close(maintenanceStopCh)
		maintenanceStopCh = nil
	}

	if listener != nil {
		listener.Close()
	}

	log.Printf("[Core] instance stopped")
}

func acceptLoop(listener net.Listener, inboundTag string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Printf("[Core] listener closed, acceptLoop exiting")
			} else {
				log.Printf("[Core] accept error: %v", err)
			}
			return
		}
		go handleGeneralConnection(conn, inboundTag)
	}
}

type connContext struct {
	conn        net.Conn
	target      string
	mode        connMode
	firstFrame  []byte
	pendingData []byte
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	var ctx connContext
	ctx.conn = conn

	var err error
	switch buf[0] {
	case socks5Version:
		ctx.target, err = handleSOCKS5(conn, inboundTag)
		ctx.mode = modeSOCKS5Pending
	default:
		ctx.target, ctx.firstFrame, ctx.mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil {
		return
	}

	sniffAndRewrite(&ctx)
	resolveTarget(&ctx)

	payload := append(ctx.pendingData, ctx.firstFrame...)
	wsConn, err := connectNanoTunnel(ctx.target, "proxy", payload)
	if err != nil {
		log.Printf("[Core] connect failed target:%s err:%v", ctx.target, err)
		return
	}

	sendPendingProxyResponse(&ctx)

	pipeDirect(conn, wsConn, ctx.target)
}

func sendPendingProxyResponse(ctx *connContext) {
	switch ctx.mode {
	case modeSOCKS5Pending:
		ctx.conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		ctx.mode = modeResponded
	case modeHTTPSPending:
		ctx.conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		ctx.mode = modeResponded
	}
}

func sniffAndRewrite(ctx *connContext) {
	if globalSniffer == nil || !globalSniffer.config.Enabled {
		return
	}

	host, port, err := net.SplitHostPort(ctx.target)
	if err != nil || !isIPAddress(host) {
		return
	}

	switch ctx.mode {
	case modeSOCKS5Pending, modeHTTPSPending:
		sendPendingProxyResponse(ctx)

		sniffBuf := make([]byte, 2048)
		ctx.conn.SetReadDeadline(time.Now().Add(sniffReadTimeout))
		n, readErr := ctx.conn.Read(sniffBuf)
		ctx.conn.SetReadDeadline(time.Time{})

		if readErr == nil && n > 0 {
			ctx.pendingData = sniffBuf[:n]
			if r := globalSniffer.Sniff(ctx.pendingData); r.Success {
				log.Printf("[Sniff] %s→%s protocol:%s", host, r.Domain, r.Protocol)
				ctx.target = net.JoinHostPort(r.Domain, port)
			}
		}

	case modeHTTPPlain:
		if r := globalSniffer.Sniff(ctx.firstFrame); r.Success {
			log.Printf("[Sniff] %s→%s protocol:%s", host, r.Domain, r.Protocol)
			ctx.target = net.JoinHostPort(r.Domain, port)
		}
	}
}

func resolveTarget(ctx *connContext) {
	if globalDNSResolver == nil {
		return
	}

	host, port, err := net.SplitHostPort(ctx.target)
	if err != nil || isIPAddress(host) {
		return
	}

	resolved := globalDNSResolver.ResolveIP(host)
	if resolved != host {
		ctx.target = net.JoinHostPort(resolved, port)
		log.Printf("[DNS] %s→%s", host, resolved)
	}
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
	default:
		return strings.Contains(target, rule.Value)
	}
}

func connectNanoTunnel(target, outboundTag string, payload []byte) (*SafeWS, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, &TunnelError{Stage: "settings", Err: errors.New("outbound not found: " + outboundTag)}
	}

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 {
		fallback = parts[1]
	}

	socks5Addr := ""
	if settings.ForwarderSettings != nil {
		socks5Addr = settings.ForwarderSettings.Socks5Address
	}

	attemptDial := func() (*SafeWS, error) {
		node, logMsg := selectNode(target, settings)
		log.Print(logMsg)

		backend := selectBackend(node.Backends, target)
		if backend.IP == "" {
			backend.IP = settings.ServerIP
		}

		start := time.Now()
		wsConn, err := dialZeusWebSocket(node.Domain, backend, secretKey)
		if err != nil {
			return nil, &TunnelError{Stage: "websocket_handshake", Err: err}
		}

		if backend.IP != "" {
			log.Printf("[Core] new tunnel SNI:%s real:%s:%s latency:%dms",
				node.Domain, backend.IP, backend.Port, time.Since(start).Milliseconds())
		}

		safe := &SafeWS{conn: wsConn}

		if err := sendNanoHeaderV2(safe, target, payload, socks5Addr, fallback); err != nil {
			wsConn.Close()
			return nil, &TunnelError{Stage: "send_header", Err: err}
		}

		return safe, nil
	}

	ws, err := attemptDial()
	if err != nil && len(settings.NodePool) > 1 {
		log.Printf("[Core] retry after err:%v", err)
		ws, err = attemptDial()
	}
	return ws, err
}

func selectNode(target string, settings ProxySettings) (Node, string) {
	for _, rule := range routingMap {
		if match(rule, target) {
			strategy := rule.Strategy
			if strategy == "" {
				strategy = settings.Strategy
			}
			return rule.Node, fmt.Sprintf("[Core] rule-hit target:%s node:%s rule:%s strategy:%s",
				target, rule.Node.Domain, rule.Value, strategy)
		}
	}

	if len(settings.NodePool) == 0 {
		return Node{}, "[Core] no nodes in pool"
	}

	strategy := settings.Strategy
	var node Node
	switch strategy {
	case "rr":
		idx := atomic.AddUint64(&globalRRIndex, 1)
		node = settings.NodePool[idx%uint64(len(settings.NodePool))]
	case "hash":
		h := md5.Sum([]byte(target))
		hashVal := binary.BigEndian.Uint64(h[:8])
		node = settings.NodePool[hashVal%uint64(len(settings.NodePool))]
	default:
		node = settings.NodePool[rand.Intn(len(settings.NodePool))]
	}
	return node, fmt.Sprintf("[Core] lb target:%s node:%s strategy:%s", target, node.Domain, strategy)
}

func selectBackend(backends []Backend, key string) Backend {
	switch len(backends) {
	case 0:
		return Backend{}
	case 1:
		return backends[0]
	}
	total := 0
	for _, b := range backends {
		total += b.Weight
	}
	h := md5.Sum([]byte(key))
	hashVal := binary.BigEndian.Uint64(h[:8])
	if total == 0 {
		return backends[int(hashVal%uint64(len(backends)))]
	}

	hashSlot := int(hashVal % uint64(total))
	cur := 0
	for _, b := range backends {
		cur += b.Weight
		if hashSlot < cur {
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
	headers := http.Header{}
	headers.Add("Host", sniHost)
	headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
		HandshakeTimeout: wsHandshakeTimeout,
	}
	if backend.IP != "" {
		dialer.NetDial = func(network, _ string) (net.Conn, error) {
			return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), wsHandshakeTimeout)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws handshake status:%d", resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

func pipeDirect(local net.Conn, ws *SafeWS, target string) {
	var upBytes, downBytes int64
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			mt, r, err := ws.NextReader()
			if err != nil {
				log.Printf("[Pipe] downstream closed target:%s err:%v", target, err)
				break
			}
			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				if n > 0 {
					atomic.AddInt64(&downBytes, n)
				}
				if err != nil {
					log.Printf("[Pipe] downstream copy failed target:%s err:%v", target, err)
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
				werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				if werr != nil {
					log.Printf("[Pipe] upstream write failed target:%s err:%v", target, werr)
					break
				}
			}
			if err != nil {
				log.Printf("[Pipe] upstream read closed target:%s err:%v", target, err)
				break
			}
		}
		ws.Close()
	}()

	wg.Wait()

	log.Printf("[Stats] %s up:%s down:%s time:%v",
		target, formatBytes(upBytes), formatBytes(downBytes), time.Since(start).Round(time.Second))
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

func sendNanoHeaderV2(wsConn *SafeWS, target string, payload []byte, s5, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)

	portVal, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	port := uint16(portVal)

	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = ip.String()
	}

	hb, s5b, fbb := []byte(host), []byte(s5), []byte(fb)
	if len(hb) > 255 || len(s5b) > 255 || len(fbb) > 255 {
		return errors.New("field length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hb)))
	buf.Write(hb)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	buf.Write(pb)
	buf.WriteByte(byte(len(s5b)))
	if len(s5b) > 0 {
		buf.Write(s5b)
	}
	buf.WriteByte(byte(len(fbb)))
	if len(fbb) > 0 {
		buf.Write(fbb)
	}
	if len(payload) > 0 {
		buf.Write(payload)
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

func handleSOCKS5(conn net.Conn, _ string) (string, error) {
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeBuf); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	var host string
	switch header[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		d := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, d); err != nil {
			return "", err
		}
		host = string(d)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("unsupported SOCKS5 atype:%d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func handleHTTP(conn net.Conn, initialData []byte, _ string) (string, []byte, connMode, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", nil, modeResponded, err
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
		return target, nil, modeHTTPSPending, nil
	}

	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), modeHTTPPlain, nil
}
