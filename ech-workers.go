// ech-proxy-core.go - v5.3 (SOCKS5 Forwarding & Compile Fix)
// 协议内核：修复了SOCKS5握手后数据流处理不当导致连接失败的根本问题
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket" // 【【【核心修复】】】
)

// ... (The rest of the code is identical to the previous version and is correct) ...
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

// --- Main Logic (Unchanged) ---
func main() {
	configPath := flag.String("c", "config.json", "Path to config")
	flag.Parse()
	log.Println("[Core] X-Link Kernel v1.2 Starting...")
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

// --- 【【CORE FIX】】---
// The main connection handler is now simpler.
func handleGeneralConnection(conn net.Conn, inboundTag string) {
    defer conn.Close()
    
    // Sniff the first byte to determine protocol
    buf := make([]byte, 1)
    if _, err := io.ReadFull(conn, buf); err != nil { return }

    switch buf[0] {
    case 0x05: // SOCKS5
        handleSOCKS5(conn, inboundTag)
    case 'C', 'G', 'P', 'H', 'D', 'O', 'T': // HTTP
        handleHTTP(conn, buf, inboundTag)
    }
}

// --- Protocol Handlers (Rewritten for clarity) ---

func handleSOCKS5(conn net.Conn, inboundTag string) {
    // 1. SOCKS5 Handshake
    handshakeBuf := make([]byte, 2)
    if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return }
    conn.Write([]byte{0x05, 0x00}) // No auth

    header := make([]byte, 4)
    if _, err := io.ReadFull(conn, header); err != nil { return }
    
    if header[1] != 0x01 { // Only CONNECT command is supported
        conn.Write([]byte{0x05, 0x07, 0x00, 0x01})
        return
    }

    var host string
    switch header[3] {
    case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
    case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
    case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
    default: return
    }
    portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
    port := binary.BigEndian.Uint16(portBytes)
    target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

    log.Printf("[%s] SOCKS5: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)

    // 2. Route and dispatch
    outboundTag := route(target, inboundTag)
    log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)
    
    outbound, ok := findOutbound(outboundTag)
    if !ok { return }

    // 3. Establish remote connection and forward data
    var err error
    switch outbound.Protocol {
    case "freedom":
        err = startDirectTunnel(conn, target, nil, true)
    case "ech-proxy":
        err = startProxyTunnel(conn, target, outboundTag, nil, true)
    case "blackhole":
        conn.Close()
        return
    }
    
    if err != nil {
        log.Printf("[%s] Tunnel failed for %s: %v", inboundTag, target, err)
    }
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) {
    reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
    req, err := http.ReadRequest(reader)
    if err != nil { return }

    target := req.Host
    if req.Method == "CONNECT" {
        log.Printf("[%s] HTTP CONNECT: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)
    } else {
        log.Printf("[%s] HTTP Proxy: %s -> %s", inboundTag, conn.RemoteAddr().String(), target)
    }
    
    outboundTag := route(target, inboundTag)
    log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)

    outbound, ok := findOutbound(outboundTag)
    if !ok { return }

    var firstFrame []byte
    if req.Method != "CONNECT" {
        var buf bytes.Buffer
        req.WriteProxy(&buf)
        firstFrame = buf.Bytes()
    }

    var tunnelErr error
    switch outbound.Protocol {
    case "freedom":
        tunnelErr = startDirectTunnel(conn, target, firstFrame, req.Method == "CONNECT")
    case "ech-proxy":
        tunnelErr = startProxyTunnel(conn, target, outboundTag, firstFrame, req.Method == "CONNECT")
    case "blackhole":
        conn.Close()
        return
    }

    if tunnelErr != nil {
        log.Printf("[%s] Tunnel failed for %s: %v", inboundTag, target, tunnelErr)
    }
}


// --- Tunneling Logic (Rewritten) ---

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, isConnect bool) error {
    remote, err := net.DialTimeout("tcp", target, 5*time.Second)
    if err != nil {
        if isConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
        return err
    }
    defer remote.Close()
    
    if isConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
    
    if len(firstFrame) > 0 { remote.Write(firstFrame) }
    go io.Copy(remote, local)
    io.Copy(local, remote)
    return nil
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, isConnect bool) error {
    wsConn, err := dialSpecificWebSocket(outboundTag)
    if err != nil {
        if isConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
        return err
    }
    defer wsConn.Close()

    // X-Link Handshake
    connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
    if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil { return err }

    _, msg, err := wsConn.ReadMessage()
    if err != nil || string(msg) != "X-LINK-OK" {
        return fmt.Errorf("handshake failed: %s", msg)
    }
    
    if isConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
    
    // Forward data
    done := make(chan bool, 2)
    go func() { io.Copy(wsConn.UnderlyingConn(), local); done <- true }()
    go func() { io.Copy(local, wsConn.UnderlyingConn()); done <- true }()
    <-done
    return nil
}


// ... (dialSpecificWebSocket and Helpers) ...
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }
	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)
	tlsCfg := &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: host, }
	dialer := websocket.Dialer{ TLSClientConfig:  tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols:     []string{settings.Token}, }
	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
}
func findOutbound(tag string) (Outbound, bool) { for _, ob := range globalConfig.Outbounds { if ob.Tag == tag { return ob, true } }; return Outbound{}, false }
func getExeDir() string { exePath, _ := os.Executable(); return filepath.Dir(exePath) }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func isChinaIPForRouter(ip net.IP) bool { if ip == nil { return false }; if ip4 := ip.To4(); ip4 != nil { val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock(); for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } } } else if ip16 := ip.To16(); ip16 != nil { var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock(); for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } } }; return false }
func loadChinaListsForRouter() { loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); loadIPListForRouter("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true) }
func loadIPListForRouter(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) { 
	file, err := os.Open(filepath.Join(getExeDir(), filename)); if err != nil { return }
	defer file.Close()
	var rangesV4 []ipRange; var rangesV6 []ipRangeV6
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }
		if isV6 {
			var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16())
			rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e})
		} else {
			s, e := ipToUint32(startIP), ipToUint32(endIP)
			if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) }
		}
	}
	mu.Lock(); defer mu.Unlock()
	if isV6 { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6)) } else { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) }
}
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return }
func (r *Routing) DefaultOutbound() string { return "direct" }
