// core/core.go (v5.2 Route Engine Fixed)
package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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
	ServerIP  string `json:"server_ip,omitempty"`
	Token     string `json:"token"`
	EchDomain string `json:"ech_domain,omitempty"`
	DnsWorker string `json:"dns_worker,omitempty"`
	DnsPublic string `json:"dns_public,omitempty"`
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

type ipRange struct{ start uint32; end uint32 }
type ipRangeV6 struct{ start [16]byte; end [16]byte }

type wsWriter struct{ *websocket.Conn }

func (w wsWriter) Write(p []byte) (int, error) {
	err := w.Conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil { return 0, err }
	return len(p), nil
}

// ======================== Core Logic ========================

func buildBinaryHandshakeFrame(target string, firstFrame []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil { return nil, err }
	port, err := strconv.Atoi(portStr)
	if err != nil { return nil, err }
	var addrBuffer bytes.Buffer
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		addrBuffer.WriteByte(0x01); addrBuffer.Write(ip.To4())
	} else if ip != nil && ip.To16() != nil {
		addrBuffer.WriteByte(0x04); addrBuffer.Write(ip.To16())
	} else {
		if len(host) > 255 { return nil, errors.New("domain too long") }
		addrBuffer.WriteByte(0x03); addrBuffer.WriteByte(byte(len(host))); addrBuffer.WriteString(host)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	addrBuffer.Write(portBytes)
	var finalFrame bytes.Buffer
	finalFrame.WriteByte(0x01); finalFrame.WriteByte(0x01)
	finalFrame.Write(addrBuffer.Bytes())
	finalFrame.Write(firstFrame)
	return finalFrame.Bytes(), nil
}

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, fmt.Errorf("config parse error: %w", err) }
	loadChinaListsForRouter()
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds configured") }
	var listeners []net.Listener
	for _, inbound := range globalConfig.Inbounds {
		listener, err := net.Listen("tcp", inbound.Listen)
		if err != nil {
			log.Printf("[Error] Listen failed on %s: %v", inbound.Listen, err)
			for _, l := range listeners { l.Close() }
			return nil, err
		}
		log.Printf("[Inbound] Listening on %s (%s)", inbound.Listen, inbound.Tag)
		listeners = append(listeners, listener)
		go func(l net.Listener, tag string) {
			for {
				conn, err := l.Accept()
				if err != nil { log.Printf("[Core] Listener closed: %v", err); break }
				go handleGeneralConnection(conn, tag)
			}
		}(listener, inbound.Tag)
	}
	return &multiListener{listeners: listeners}, nil
}

type multiListener struct { listeners []net.Listener }
func (ml *multiListener) Accept() (net.Conn, error) { return nil, nil }
func (ml *multiListener) Close() error { for _, l := range ml.listeners { l.Close() }; return nil }
func (ml *multiListener) Addr() net.Addr { if len(ml.listeners) > 0 { return ml.listeners[0].Addr() }; return nil }

func parseOutbounds() {
	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil { proxySettingsMap[outbound.Tag] = settings }
		}
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
	handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf)
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4); io.ReadFull(conn, header)
	if header[1] != 0x01 { return "", errors.New("unsupported SOCKS5 command") }
	var host string
	switch header[3] {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return target, nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil { return "", nil, 0, err }
	target := req.Host
	if !strings.Contains(target, ":") { target += ":80" }
	mode := 2
	if req.Method == "CONNECT" { return target, nil, mode, nil }
	mode = 3; var buf bytes.Buffer; req.WriteProxy(&buf)
	return target, buf.Bytes(), mode, nil
}

// [关键修复] 路由逻辑
func route(target, inboundTag string) string {
	host, _, _ := net.SplitHostPort(target); if host == "" { host = target }
	
	for _, rule := range globalConfig.Routing.Rules {
		isMatch := true // 假设匹配，除非发现不匹配的条件

		// 1. 检查 InboundTag
		if len(rule.InboundTag) > 0 {
			tagMatch := false
			for _, t := range rule.InboundTag {
				if t == inboundTag { tagMatch = true; break }
			}
			if !tagMatch { isMatch = false }
		}
		if !isMatch { continue }

		// 2. 检查 Domain
		if len(rule.Domain) > 0 {
			domainMatch := false
			for _, d := range rule.Domain {
				if strings.Contains(host, d) { domainMatch = true; break }
			}
			if !domainMatch { isMatch = false }
		}
		if !isMatch { continue }

		// 3. 检查 GeoIP
		if rule.GeoIP == "cn" {
			cnMatch := false
			if isChinaIPForRouter(net.ParseIP(host)) { cnMatch = true }
			else {
				ips, err := net.LookupIP(host)
				if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) { cnMatch = true }
			}
			if !cnMatch { isMatch = false }
		}
		if !isMatch { continue }

		// 如果所有定义的条件都满足（或者没有定义条件），则匹配成功
		return rule.OutboundTag
	}

	if globalConfig.Routing.DefaultOutbound != "" { return globalConfig.Routing.DefaultOutbound }
	return "direct"
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

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, mode int) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { return err }
	defer remote.Close()
	if mode == 1 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	else if mode == 2 { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	if len(firstFrame) > 0 { remote.Write(firstFrame) }
	go io.Copy(remote, local); io.Copy(local, remote)
	return nil
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	wsConn, err := dialSpecificWebSocket(outboundTag); if err != nil { return err }
	defer wsConn.Close()
	noiseCount := mathrand.Intn(4) + 1
	for i := 0; i < noiseCount; i++ {
		noiseSize := mathrand.Intn(201) + 50; noise := make([]byte, noiseSize); rand.Read(noise)
		wsConn.WriteMessage(websocket.BinaryMessage, noise)
		time.Sleep(time.Duration(mathrand.Intn(51)+10) * time.Millisecond)
	}
	handshakeFrame, err := buildBinaryHandshakeFrame(target, firstFrame); if err != nil { return err }
	if err := wsConn.WriteMessage(websocket.BinaryMessage, handshakeFrame); err != nil { return err }
	_, msg, err := wsConn.ReadMessage()
	if err != nil || len(msg) != 2 || msg[0] != 0x01 || msg[1] != 0x00 { return fmt.Errorf("binary handshake failed") }
	if mode == 1 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	else if mode == 2 { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	done := make(chan bool, 2)
	go func() { io.Copy(wsWriter{wsConn}, local); wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); done <- true }()
	go func() {
		for {
			msgType, msg, err := wsConn.ReadMessage()
			if err != nil { local.Close(); done <- true; return }
			if msgType == websocket.BinaryMessage { local.Write(msg) }
		}
	}()
	<-done
	return nil
}

func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]; if !ok { return nil, errors.New("settings not found") }
	host, port, path, _ := parseServerAddr(settings.Server)
	sni := host; if settings.EchDomain != "" { sni = settings.EchDomain }
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: sni}
	dialer := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{settings.Token}}
	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second) }
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
}

func findOutbound(tag string) (Outbound, bool) { for _, ob := range globalConfig.Outbounds { if ob.Tag == tag { return ob, true } }; return Outbound{}, false }
func getExeDir() string { exePath, _ := os.Executable(); return filepath.Dir(exePath) }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func isChinaIPForRouter(ip net.IP) bool { if ip == nil { return false }; if ip4 := ip.To4(); ip4 != nil { val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock(); for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } } }; return false }
func loadChinaListsForRouter() { loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false) }
func loadIPListForRouter(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) { file, err := os.Open(filepath.Join(getExeDir(), filename)); if err != nil { return }; defer file.Close(); var rangesV4 []ipRange; scanner := bufio.NewScanner(file); for scanner.Scan() { parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }; startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }; if !isV6 { s, e := ipToUint32(startIP), ipToUint32(endIP); if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) } } }; mu.Lock(); defer mu.Unlock(); reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return }
