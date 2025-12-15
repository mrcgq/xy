package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// JsonEnvelope 用于 WebSocket 消息封装
type JsonEnvelope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	TS   int64  `json:"ts"`
	Data string `json:"data"`
}

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
	Server   string `json:"server"`
	ServerIP string `json:"server_ip"`
	Token    string `json:"token"`
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
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	// 暂时注释掉路由相关的全局变量，以解决 unused 报错
	// chinaIPRanges     []ipRange
	// chinaIPV6Ranges   []ipRangeV6
	// chinaIPRangesMu   sync.RWMutex
	// chinaIPV6RangesMu sync.RWMutex
)

// type ipRange struct{ start uint32; end uint32 }
// type ipRangeV6 struct{ start [16]byte; end [16]byte }

// ======================== Core Logic ========================

func wrapAsJson(payload []byte) ([]byte, error) {
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
	envelope := JsonEnvelope{
		ID:   fmt.Sprintf("msg_%x", idBytes),
		Type: "sync_data",
		TS:   time.Now().UnixMilli(),
		Data: base64.StdEncoding.EncodeToString(payload),
	}
	return json.Marshal(envelope)
}

func unwrapFromJson(rawMsg []byte) ([]byte, error) {
	var envelope JsonEnvelope
	if err := json.Unmarshal(rawMsg, &envelope); err != nil {
		return nil, fmt.Errorf("not a valid json envelope: %w", err)
	}
	if envelope.Type == "pong" {
		return nil, nil
	}
	if envelope.Type != "sync_data" {
		return nil, errors.New("not a sync_data type message")
	}
	return base64.StdEncoding.DecodeString(envelope.Data)
}

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	
	// 暂时禁用 IP 库加载，避免依赖本地文件
	// loadChinaListsForRouter()
	
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen failed on %s: %v", inbound.Listen, err)
	}
	log.Printf("[Core] SOCKS5 Listening on %s", inbound.Listen)

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

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	var target string
	var err error
	var firstFrame []byte
	var mode int // 1: SOCKS5, 2: CONNECT, 3: HTTP Proxy

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	default:
		return
	}

	if err != nil {
		log.Printf("[%s] Protocol handshake failed: %v", inboundTag, err)
		return
	}

	// 简单路由：直接查找名为 "proxy" 的 outbound
	// 暂时禁用复杂路由以精简依赖
	outboundTag := "proxy"
	// outboundTag = route(target, inboundTag)

	log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr(), target, outboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeBuf); err != nil {
		return "", err
	}
	conn.Write([]byte{0x05, 0x00})

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

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
	default:
		return "", errors.New("unsupported addr type")
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

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	if outboundTag == "direct" {
		startDirectTunnel(conn, target, firstFrame, mode)
		return
	}
	startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
}

func startDirectTunnel(local net.Conn, target string, firstFrame []byte, mode int) {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	if mode == 1 {
		local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == 2 {
		local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	if len(firstFrame) > 0 {
		remote.Write(firstFrame)
	}

	go io.Copy(remote, local)
	io.Copy(local, remote)
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		return err
	}
	defer wsConn.Close()

	connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	jsonHandshake, _ := wrapAsJson([]byte(connectMsg))

	if err := wsConn.WriteMessage(websocket.TextMessage, jsonHandshake); err != nil {
		return err
	}

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return err
	}

	okPayload, err := unwrapFromJson(msg)
	if err != nil || string(okPayload) != "X-LINK-OK" {
		return fmt.Errorf("handshake failed")
	}

	if mode == 1 {
		local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == 2 {
		local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	done := make(chan bool, 2)

	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				jsonData, _ := wrapAsJson(buf[:n])
				wsConn.WriteMessage(websocket.TextMessage, jsonData)
			}
			if err != nil {
				break
			}
		}
		done <- true
	}()

	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil {
				break
			}
			payload, _ := unwrapFromJson(msg)
			if payload != nil {
				local.Write(payload)
			}
		}
		done <- true
	}()

	<-done
	return nil
}

func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("settings not found")
	}

	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		Subprotocols:    []string{settings.Token},
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
		err = nil
	}
	return
}

/*
// 暂时注释掉路由和 IP 加载逻辑，避免 os, path/filepath, reflect, sync 等未使用包的引用错误
// 如果未来需要恢复，请确保取消注释上面的 imports

func route(target, inboundTag string) string {
	host, _, _ := net.SplitHostPort(target); if host == "" { host = target }
	for _, rule := range globalConfig.Routing.Rules {
		if len(rule.InboundTag) > 0 {
			match := false; for _, t := range rule.InboundTag { if t == inboundTag { match = true; break } }; if !match { continue }
		}
		if len(rule.Domain) > 0 { for _, d := range rule.Domain { if strings.Contains(host, d) { return rule.OutboundTag } } }
		if rule.GeoIP == "cn" {
			if isChinaIPForRouter(net.ParseIP(host)) { return rule.OutboundTag }
			ips, err := net.LookupIP(host); if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) { return rule.OutboundTag }
		}
	}
	if globalConfig.Routing.DefaultOutbound != "" { return globalConfig.Routing.DefaultOutbound }
	return "direct"
}

func getExeDir() string {
	exePath, _ := os.Executable(); return filepath.Dir(exePath)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip)
}

func isChinaIPForRouter(ip net.IP) bool {
	if ip == nil { return false }
	if ip4 := ip.To4(); ip4 != nil {
		val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock()
		for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } }
	} else if ip16 := ip.To16(); ip16 != nil {
		var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock()
		for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } }
	}
	return false
}

func loadChinaListsForRouter() {
	loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false)
	loadIPListForRouter("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true)
}

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
*/
