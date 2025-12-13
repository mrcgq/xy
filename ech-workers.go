// ech-proxy-core.go - v8.0 (URL Auth Edition)
// 协议内核：完全模仿 VLESS 的行为模式。
// 1. 使用 URL Query (?t=token) 传递认证，不再使用 Header。
// 2. 添加标准的 User-Agent Header 伪装成浏览器。
// 3. 保留 SOCKS5 首包修复。
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url" // 需要 url 包处理编码
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== Config Structures ========================
type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}
type Inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Protocol string `json:"protocol"`
}
type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}
type ProxySettings struct {
	Server    string `json:"server"`
	ServerIP  string `json:"server_ip"`
	Token     string `json:"token"`
}
type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	GeoIP       string   `json:"geoip,omitempty"`
	Port        []int    `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

var (
	globalConfig      Config
	proxySettingsMap  = make(map[string]ProxySettings)
	chinaIPRanges     []ipRange
	chinaIPV6Ranges   []ipRangeV6
	chinaIPRangesMu   sync.RWMutex
	chinaIPV6RangesMu sync.RWMutex
)
type ipRange struct { start uint32; end uint32 }
type ipRangeV6 struct { start [16]byte; end [16]byte }

func main() {
	configPath := flag.String("c", "config.json", "Path to config")
	flag.Parse()
	log.Println("[Core] X-Link Kernel v8.0 (URL Auth) Starting...")
	file, err := os.ReadFile(*configPath)
	if err != nil { log.Fatalf("Failed to read config: %v", err) }
	if err := json.Unmarshal(file, &globalConfig); err != nil { log.Fatalf("Config parse error: %v", err) }
	loadChinaListsForRouter()
	parseOutbounds()
	var wg sync.WaitGroup
	for _, inbound := range globalConfig.Inbounds {
		wg.Add(1)
		go func(ib Inbound) { defer wg.Done(); runInbound(ib) }(inbound)
	}
	log.Println("[Core] Engine started.")
	wg.Wait()
}

func parseOutbounds() {
    for _, outbound := range globalConfig.Outbounds {
        if outbound.Protocol == "ech-proxy" {
            var settings ProxySettings
            if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
                proxySettingsMap[outbound.Tag] = settings
            }
        }
    }
}
func runInbound(ib Inbound) {
    listener, err := net.Listen("tcp", ib.Listen)
    if err != nil { log.Printf("[Error] Listen failed on %s: %v", ib.Listen, err); return }
    log.Printf("[Inbound] Listening on %s (%s)", ib.Listen, ib.Tag)
    for {
        conn, err := listener.Accept()
        if err != nil { continue }
        go handleGeneralConnection(conn, ib.Tag)
    }
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
    defer conn.Close()
    buf := make([]byte, 1)
    if _, err := io.ReadFull(conn, buf); err != nil { return }
    var target string; var err error; var firstFrame []byte; var mode int
    switch buf[0] {
    case 0x05: target, err = handleSOCKS5(conn, inboundTag); mode = 1
    case 'C', 'G', 'P', 'H', 'D', 'O', 'T': target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
    default: return
    }
    if err != nil { log.Printf("[%s] Protocol error: %v", inboundTag, err); return }
    outboundTag := route(target, inboundTag)
    log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)
    dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
    handshakeBuf := make([]byte, 2); if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return "", err }
    conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); if _, err := io.ReadFull(conn, header); err != nil { return "", err }
    if header[1] != 0x01 { conn.Write([]byte{0x05, 0x07, 0x00, 0x01}); return "", errors.New("unsupported SOCKS5 command") }
    var host string
    switch header[3] {
    case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
    case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
    case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
    default: return "", errors.New("bad addr type")
    }
    portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes)
    target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
    log.Printf("[%s] SOCKS5: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)
    return target, nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
    reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
    req, err := http.ReadRequest(reader)
    if err != nil { return "", nil, 0, err }
    target := req.Host; mode := 2
    if req.Method == "CONNECT" { log.Printf("[%s] HTTP CONNECT: %s -> %s", inboundTag, conn.RemoteAddr().String(), target); return target, nil, mode, nil } 
    log.Printf("[%s] HTTP Proxy: %s -> %s", inboundTag, conn.RemoteAddr().String(), target); mode = 3
    var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), mode, nil
}

func route(target, inboundTag string) string {
	host, _, _ := net.SplitHostPort(target); if host == "" { host = target }
	for _, rule := range globalConfig.Routing.Rules {
		if len(rule.InboundTag) > 0 { match := false; for _, t := range rule.InboundTag { if t == inboundTag { match = true; break } }; if !match { continue } }
		if len(rule.Domain) > 0 { for _, d := range rule.Domain { if strings.Contains(host, d) { return rule.OutboundTag } } }
		if rule.GeoIP == "cn" { if isChinaIPForRouter(net.ParseIP(host)) { return rule.OutboundTag }; ips, err := net.LookupIP(host); if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) { return rule.OutboundTag } }
	}
	if globalConfig.Routing.DefaultOutbound != "" { return globalConfig.Routing.DefaultOutbound }; return "direct"
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
    outbound, ok := findOutbound(outboundTag); if !ok { return }
    var err error
    switch outbound.Protocol {
    case "freedom": err = startDirectTunnel(conn, target, firstFrame, mode)
    case "ech-proxy": err = startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
    case "blackhole": conn.Close(); return
    }
    if err != nil { log.Printf("Tunnel failed for %s: %v", target, err) }
}

const ( modeSOCKS5 = 1; modeHTTPConnect = 2; modeHTTPProxy = 3 )

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, mode int) error {
    remote, err := net.DialTimeout("tcp", target, 5*time.Second)
    if err != nil {
        if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) }
		if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
        return err
    }
    defer remote.Close()
    if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) }
    if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
    if len(firstFrame) > 0 { remote.Write(firstFrame) }
    go io.Copy(remote, local); io.Copy(local, remote); return nil
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
    // SOCKS5 修复保持不变
    if mode == modeSOCKS5 && len(firstFrame) == 0 {
        local.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
        buffer := make([]byte, 32*1024)
        n, readErr := local.Read(buffer)
        local.SetReadDeadline(time.Time{})
        if n > 0 { firstFrame = buffer[:n] }
        if readErr != nil && !os.IsTimeout(readErr) && readErr != io.EOF { return readErr }
    }

	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) }
		if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
		return err
	}
	defer wsConn.Close()

	var handshakeBuf bytes.Buffer
	addrLen := uint16(len(target))
	binary.Write(&handshakeBuf, binary.BigEndian, addrLen)
	handshakeBuf.WriteString(target)
	if len(firstFrame) > 0 { handshakeBuf.Write(firstFrame) }

	if err := wsConn.WriteMessage(websocket.BinaryMessage, handshakeBuf.Bytes()); err != nil { return err }

	if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) }
	if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }

	done := make(chan bool, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				done <- true; return
			}
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { done <- true; return }
		}
	}()
	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil { local.Close(); done <- true; return }
			if _, err := local.Write(msg); err != nil { done <- true; return }
		}
	}()
	<-done; return nil
}

// 【核心修改】将 Token 放入 URL 查询参数，并添加伪装 Header
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	host, port, path, err := parseServerAddr(settings.Server)
	if err != nil { return nil, fmt.Errorf("invalid server address: %w", err) }
	
	// 构造带 Token 的 URL
	// 格式: wss://host:port/path?t=TOKEN
	u := url.URL{Scheme: "wss", Host: net.JoinHostPort(host, port), Path: path}
	q := u.Query()
	q.Set("t", settings.Token)
	u.RawQuery = q.Encode()
	wsURL := u.String()

	// 标准 TLS 配置
	tlsCfg := &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: host }
	
	// 添加伪装 Header
	customHeader := http.Header{}
	customHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	customHeader.Add("Accept-Language", "en-US,en;q=0.9")

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}
	
	conn, _, err := dialer.Dial(wsURL, customHeader)
	return conn, err
}

func findOutbound(tag string) (Outbound, bool) { for _, ob := range globalConfig.Outbounds { if ob.Tag == tag { return ob, true } }; return Outbound{}, false }
func getExeDir() string { exePath, _ := os.Executable(); return filepath.Dir(exePath) }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func isChinaIPForRouter(ip net.IP) bool { if ip == nil { return false }; if ip4 := ip.To4(); ip4 != nil { val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock(); for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } } } else if ip16 := ip.To16(); ip16 != nil { var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock(); for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } } }; return false }
func loadChinaListsForRouter() { loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); loadIPListForRouter("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true) }
func loadIPListForRouter(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) { file, err := os.Open(filepath.Join(getExeDir(), filename)); if err != nil { return }; defer file.Close(); var rangesV4 []ipRange; var rangesV6 []ipRangeV6; scanner := bufio.NewScanner(file); for scanner.Scan() { parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }; startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }; if isV6 { var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16()); rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e}) } else { s, e := ipToUint32(startIP), ipToUint32(endIP); if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) } } }; mu.Lock(); defer mu.Unlock(); if isV6 { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6)) } else { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) } }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return }
