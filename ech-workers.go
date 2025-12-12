// ech-proxy-core.go - v4.0 Unified Engine (Full-Featured & Complete)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"net/url"
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
type ECHProxySettings struct {
	Server    string `json:"server"`
	ServerIP  string `json:"server_ip"`
	Token     string `json:"token"`
	ECHDomain string `json:"ech_domain"`
	DNSWorker string `json:"dns_worker"`
	DNSPublic string `json:"dns_public"`
}
type Routing struct {
	Rules []Rule `json:"rules"`
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	GeoIP       string   `json:"geoip,omitempty"`
	Port        []int    `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// ======================== Global State ========================

var (
	globalConfig      Config
	echConfigs        = make(map[string][]byte)
	echSettingsMap    = make(map[string]ECHProxySettings)
	chinaIPRanges     []ipRange
	chinaIPV6Ranges   []ipRangeV6
	chinaIPRangesMu   sync.RWMutex
	chinaIPV6RangesMu sync.RWMutex
)

type ipRange struct { start uint32; end uint32 }
type ipRangeV6 struct { start [16]byte; end [16]byte }

// ======================== Main Logic ========================

func main() {
	configPath := flag.String("c", "config.json", "Path to the configuration file")
	flag.Parse()

	log.Println("[Core] Loading configuration from", *configPath)
	file, err := os.ReadFile(*configPath); if err != nil { log.Fatalf("[Fatal] Failed to read config file: %v", err) }
	if err := json.Unmarshal(file, &globalConfig); err != nil { log.Fatalf("[Fatal] Failed to parse config file: %v", err) }

	log.Println("[Core] Initializing resources...")
	loadChinaListsForRouter()
	prepareAllECHConfigs()

	var wg sync.WaitGroup
	for _, inbound := range globalConfig.Inbounds {
		wg.Add(1)
		go func(ib Inbound) {
			defer wg.Done()
			runInbound(ib)
		}(inbound)
	}
	log.Println("[Core] Engine started. All inbounds are running.")
	wg.Wait()
}

func runInbound(ib Inbound) {
	listener, err := net.Listen("tcp", ib.Listen)
	if err != nil { log.Printf("[Error] Failed to listen on %s for inbound '%s': %v", ib.Listen, ib.Tag, err); return }
	defer listener.Close()
	log.Printf("[Inbound] Listening on %s for tag '%s'", ib.Listen, ib.Tag)

	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		go handleGeneralConnection(conn, ib.Tag)
	}
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	
	buf := make([]byte, 1); if _, err := conn.Read(buf); err != nil { return }

	var target string
	var err error
	var firstFrame []byte
	var mode int

	switch buf[0] {
	case 0x05:
		err = handleSOCKS5(conn, clientAddr, inboundTag)
		if err != nil { log.Printf("[Error] [%s] SOCKS5 handling failed: %v", inboundTag, err) }
		return // SOCKS5 handler manages its own tunnel
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		target, firstFrame, mode, err = parseHTTP(conn, clientAddr, buf[0])
	default:
		log.Printf("[Error] [%s] Unknown protocol from %s", inboundTag, clientAddr)
		return
	}
	
	if err != nil { log.Printf("[Error] [%s] Failed to parse request: %v", inboundTag, err); return }

	outboundTag := route(target, inboundTag)
	log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, clientAddr, target, outboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

// ======================== Routing Logic ========================

func route(target, inboundTag string) string {
	host, portStr, _ := net.SplitHostPort(target); if host == "" { host = target }
	port, _ := strconv.Atoi(portStr)

	for _, rule := range globalConfig.Routing.Rules {
		inboundMatch := false
		if len(rule.InboundTag) == 0 { inboundMatch = true } else {
			for _, tag := range rule.InboundTag { if tag == inboundTag { inboundMatch = true; break } }
		}
		if !inboundMatch { continue }

		if len(rule.Port) > 0 { for _, p := range rule.Port { if p == port { return rule.OutboundTag } } }
		if len(rule.Domain) > 0 { for _, d := range rule.Domain { if strings.Contains(host, d) { return rule.OutboundTag } } }
		if rule.GeoIP == "cn" {
			if isChinaIPForRouter(net.ParseIP(host)) { return rule.OutboundTag }
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) { return rule.OutboundTag }
		}
		// If a rule has no conditions, it's a final/default rule for that inbound
		if len(rule.Domain) == 0 && rule.GeoIP == "" && len(rule.Port) == 0 {
			return rule.OutboundTag
		}
	}
	
	// Default fallback if no rules match
	return "direct" 
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	outbound, found := findOutbound(outboundTag)
	if !found { log.Printf("[Error] Outbound tag '%s' not found", outboundTag); sendErrorResponse(conn, mode); return }
	
	var err error
	switch outbound.Protocol {
	case "freedom": 
		err = handleDirect(conn, target, firstFrame, mode)
	case "blackhole": 
		conn.Close()
	case "ech-proxy":
		err = handleProxy(conn, target, outboundTag, firstFrame, mode)
	default:
		log.Printf("[Error] Unknown outbound protocol: %s", outbound.Protocol)
		sendErrorResponse(conn, mode)
	}
	if err != nil {
		log.Printf("[Dispatch] Handling for %s failed: %v", target, err)
	}
}


// ======================== Full Protocol Handlers (Restored from v3.x) ========================

const ( modeSOCKS5 = 1; modeHTTPConnect = 2; modeHTTPProxy = 3 )

func handleSOCKS5(conn net.Conn, clientAddr, inboundTag string) error {
	if _, err := conn.Read(make([]byte, 1)); err != nil { return err } // nmethods
	if _, err := conn.Read(make([]byte, 1)); err != nil { return err } // methods
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return err }

	header := make([]byte, 4); if _, err := io.ReadFull(conn, header); err != nil { return err }
	cmd, atyp := header[1], header[3]; var host string
	switch atyp {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	default: return errors.New("unsupported address type")
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	switch cmd {
	case 0x01: // CONNECT
		log.Printf("[%s] SOCKS5: %s -> %s", inboundTag, clientAddr, target)
		outboundTag := route(target, inboundTag)
		log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, clientAddr, target, outboundTag)
		dispatch(conn, target, outboundTag, nil, modeSOCKS5)
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(conn, clientAddr, inboundTag)
	default:
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
	return nil
}

func parseHTTP(conn net.Conn, clientAddr string, firstByte byte) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }
	if req.Method == "CONNECT" {
		log.Printf("[%s] HTTP: %s -> CONNECT %s", conn.LocalAddr().(*net.TCPAddr).Port, clientAddr, req.Host)
		return req.Host, nil, modeHTTPConnect, nil
	}
	log.Printf("[%s] HTTP: %s -> %s %s", conn.LocalAddr().(*net.TCPAddr).Port, clientAddr, req.Method, req.URL.Host)
	var buf bytes.Buffer
	if err := req.WriteProxy(&buf); err != nil { return "", nil, 0, err }
	return req.URL.Host, buf.Bytes(), modeHTTPProxy, nil
}

// ======================== Tunneling and Dispatch Logic (Restored from v3.x) ========================

func handleDirect(clientConn net.Conn, target string, firstFrame []byte, mode int) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { sendErrorResponse(clientConn, mode); return err }
	defer remote.Close()
	if err := sendSuccessResponse(clientConn, mode); err != nil { return err }
	if len(firstFrame) > 0 { remote.Write(firstFrame) }
	go io.Copy(remote, clientConn)
	io.Copy(clientConn, remote)
	return nil
}

func handleProxy(clientConn net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	wsConn, err := dialSpecificWebSocket(outboundTag); if err != nil { sendErrorResponse(clientConn, mode); return err }
	defer wsConn.Close()
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil { sendErrorResponse(clientConn, mode); return err }
	_, msg, err := wsConn.ReadMessage(); if err != nil || string(msg) != "CONNECTED" { sendErrorResponse(clientConn, mode); return fmt.Errorf("handshake failed: %s", string(msg)) }
	if err := sendSuccessResponse(clientConn, mode); err != nil { return err }

	done := make(chan bool, 2)
	go func() { buf := make([]byte, 32*1024); for { n, err := clientConn.Read(buf); if err != nil { wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); done <- true; return }; if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { done <- true; return } } }()
	go func() { for { _, msg, err := wsConn.ReadMessage(); if err != nil { clientConn.Close(); done <- true; return }; if _, err := clientConn.Write(msg); err != nil { done <- true; return } } }()
	<-done
	return nil
}


// ======================== Full Helper Functions (Restored & Adapted) ========================

func findOutbound(tag string) (Outbound, bool) { for _, ob := range globalConfig.Outbounds { if ob.Tag == tag { return ob, true } }; return Outbound{}, false }
func sendErrorResponse(conn net.Conn, mode int) { switch mode { case modeSOCKS5, modeHTTPConnect: conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}); case modeHTTPProxy: conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) } }
func sendSuccessResponse(conn net.Conn, mode int) error { var err error; switch mode { case modeSOCKS5: _, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); case modeHTTPConnect: _, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); case modeHTTPProxy: return nil }; return err }
func getExeDir() string { exePath, err := os.Executable(); if err != nil { return "." }; return filepath.Dir(exePath) }
var httpClient = &http.Client{ Timeout: 30 * time.Second, Transport: &http.Transport{ DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return (&net.Dialer{ Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, }).DialContext(ctx, "tcp4", addr) }, }, }
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) { roots, err := x509.SystemCertPool(); if err != nil { return nil, err }; config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots}; v := reflect.ValueOf(config).Elem(); f := v.FieldByName("EncryptedClientHelloConfigList"); if !f.IsValid() || !f.CanSet() { return nil, errors.New("unsupported ECH") }; f.Set(reflect.ValueOf(echList)); return config, nil }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func isChinaIPForRouter(ip net.IP) bool { if ip == nil { return false }; if ip4 := ip.To4(); ip4 != nil { val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock(); for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } } } else if ip16 := ip.To16(); ip16 != nil { var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock(); for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } } }; return false }
func loadChinaListsForRouter() { if err := loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); err != nil { log.Printf("[GeoIP] Failed to load IPv4 list: %v", err) }; if err := loadIPListForRouter("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true); err != nil { log.Printf("[GeoIP] Failed to load IPv6 list: %v", err) } }
func loadIPListForRouter(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) error { filePath := filepath.Join(getExeDir(), filename); if _, err := os.Stat(filePath); os.IsNotExist(err) { url := "https://mirror.ghproxy.com/https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/" + filename; log.Printf("[GeoIP] Downloading %s...", filename); if err := downloadFile(filePath, url); err != nil { return err } }; file, err := os.Open(filePath); if err != nil { return err }; defer file.Close(); var rangesV4 []ipRange; var rangesV6 []ipRangeV6; scanner := bufio.NewScanner(file); for scanner.Scan() { parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }; startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }; if isV6 { var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16()); rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e}) } else { s, e := ipToUint32(startIP), ipToUint32(endIP); if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) } } }; mu.Lock(); defer mu.Unlock(); if isV6 { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6)) } else { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) }; return nil }
func downloadFile(path, url string) error { resp, err := httpClient.Get(url); if err != nil { return err }; defer resp.Body.Close(); if resp.StatusCode != 200 { return fmt.Errorf("HTTP status %d", resp.StatusCode) }; data, err := io.ReadAll(resp.Body); if err != nil { return err }; return os.WriteFile(path, data, 0644) }
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) { settings, ok := echSettingsMap[outboundTag]; if !ok { return nil, errors.New("outbound settings not found") }; echConfig, ok := echConfigs[outboundTag]; if !ok { return nil, errors.New("ECH config not found for outbound") }; host, port, path, err := parseServerAddr(settings.Server); if err != nil { return nil, err }; wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path); tlsCfg, err := buildTLSConfigWithECH(host, echConfig); if err != nil { return nil, err }; dialer := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{settings.Token}}; if settings.ServerIP != "" { dialer.NetDial = func(n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 10*time.Second) } }; conn, _, err := dialer.Dial(wsURL, nil); if err != nil { return nil, err }; return conn, nil }
func prepareAllECHConfigs() { for _, outbound := range globalConfig.Outbounds { if outbound.Protocol == "ech-proxy" { var settings ECHProxySettings; if err := json.Unmarshal(outbound.Settings, &settings); err != nil { log.Printf("[Error] Failed to parse settings for outbound '%s'", outbound.Tag); continue }; echSettingsMap[outbound.Tag] = settings; log.Printf("[ECH] Preparing config for outbound '%s'...", outbound.Tag); var echBase64 string; var err error; if settings.DNSWorker != "" { echBase64, err = queryHTTPSRecord(settings.ECHDomain, settings.DNSWorker) }; if err != nil || echBase64 == "" { if settings.DNSPublic != "" { echBase64, err = queryHTTPSRecord(settings.ECHDomain, settings.DNSPublic) } }; if err != nil { log.Printf("[Error] Failed to get ECH for outbound '%s': %v", outbound.Tag, err); continue }; raw, err := base64.StdEncoding.DecodeString(echBase64); if err != nil { log.Printf("[Error] Failed to decode ECH for outbound '%s': %v", outbound.Tag, err); continue }; echConfigs[outbound.Tag] = raw; log.Printf("[ECH] Config loaded for outbound '%s', length: %d", outbound.Tag, len(raw)) } } }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return }
func queryHTTPSRecord(domain, dnsServer string) (string, error) { if !strings.HasPrefix(dnsServer, "https://") && !strings.HasPrefix(dnsServer, "http://") { dnsServer = "https://" + dnsServer }; return queryDoH(domain, dnsServer) }
func queryDoH(domain, dohURL string) (string, error) { u, err := url.Parse(dohURL); if err != nil { return "", err }; dnsQuery := buildDNSQuery(domain, typeHTTPS); q := u.Query(); q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsQuery)); u.RawQuery = q.Encode(); req, err := http.NewRequest("GET", u.String(), nil); if err != nil { return "", err }; req.Header.Set("Accept", "application/dns-message"); resp, err := httpClient.Do(req); if err != nil { return "", err }; defer resp.Body.Close(); if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("HTTP %d", resp.StatusCode) }; body, err := io.ReadAll(resp.Body); if err != nil { return "", err }; return parseDNSResponse(body) }
func buildDNSQuery(domain string, qtype uint16) []byte { var q []byte; q = append(q, []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0} ...); for _, label := range strings.Split(domain, ".") { q = append(q, byte(len(label))); q = append(q, label...) }; q = append(q, 0); q = binary.BigEndian.AppendUint16(q, qtype); q = binary.BigEndian.AppendUint16(q, 1); return q }
func parseDNSResponse(r []byte) (string, error) { if len(r) < 12 || binary.BigEndian.Uint16(r[6:8]) == 0 { return "", errors.New("no answer records") }; offset := 12; for r[offset] != 0 { offset += int(r[offset]) + 1 }; offset += 5; for { if offset+10 > len(r) { break }; offset += 2; if r[offset-2]&0xC0 == 0xC0 { } else { for r[offset-1] != 0 { offset += int(r[offset-1]) + 1 } }; rrType := binary.BigEndian.Uint16(r[offset : offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(r[offset : offset+2]); offset += 2; if offset+int(dataLen) > len(r) { break }; data := r[offset : offset+int(dataLen)]; offset += int(dataLen); if rrType == typeHTTPS { if ech := parseHTTPSRecord(data); ech != "" { return ech, nil } } }; return "", errors.New("no HTTPS record found") }
func parseHTTPSRecord(data []byte) string { if len(data) < 2 { return "" }; offset := 2; for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++; for offset+4 <= len(data) { key := binary.BigEndian.Uint16(data[offset:offset+2]); length := binary.BigEndian.Uint16(data[offset+2:offset+4]); offset += 4; if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length); if key == 5 { return base64.StdEncoding.EncodeToString(value) } }; return "" }
func handleUDPAssociate(tcpConn net.Conn, clientAddr, inboundTag string) { udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0"); udpConn, err := net.ListenUDP("udp", udpAddr); if err != nil { log.Printf("[UDP] %s listen failed: %v", clientAddr, err); return }; lAddr := udpConn.LocalAddr().(*net.UDPAddr); port := lAddr.Port; log.Printf("[UDP] %s association opened on port: %d", clientAddr, port); resp := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}; tcpConn.Write(resp); go func() { tcpConn.Read(make([]byte, 1)); udpConn.Close() }(); buf := make([]byte, 2048); for { n, addr, err := udpConn.ReadFromUDP(buf); if err != nil { break }; go processUDP(udpConn, addr, buf[:n], clientAddr, inboundTag) } }
func processUDP(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, tcpClientAddr, inboundTag string) { if len(data) < 6 || data[2] != 0 { return }; pos := 3; atyp := data[pos]; pos++; var host string; switch atyp { case 1: host = net.IP(data[pos : pos+4]).String(); pos += 4; case 3: host = string(data[pos+1 : pos+1+int(data[pos])]); pos += 1 + int(data[pos]); case 4: host = net.IP(data[pos : pos+16]).String(); pos += 16 }; port := binary.BigEndian.Uint16(data[pos : pos+2]); pos += 2; payload := data[pos:]; if port == 53 { log.Printf("[UDP-DNS] %s -> %s:%d (DoH query)", tcpClientAddr, host, port); go func() { outboundTag := route(fmt.Sprintf("%s:%d", host, port), inboundTag); outbound, ok := findOutbound(outboundTag); if !ok || outbound.Protocol != "ech-proxy" { log.Printf("[UDP-DNS] No ech-proxy outbound found for DNS query via tag %s", outboundTag); return }; resp, err := queryDoHForProxy(payload, outboundTag); if err == nil { resHdr := make([]byte, pos); copy(resHdr, data[:pos]); final := append(resHdr, resp...); conn.WriteToUDP(final, clientAddr) } }() } }
func queryDoHForProxy(dnsQuery []byte, outboundTag string) ([]byte, error) { echConfig, ok := echConfigs[outboundTag]; if !ok { return nil, errors.New("ECH config not found") }; settings := echSettingsMap[outboundTag]; tlsCfg, _ := buildTLSConfigWithECH("cloudflare-dns.com", echConfig); tr := &http.Transport{TLSClientConfig: tlsCfg}; if settings.ServerIP != "" { tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 10*time.Second) } }; client := &http.Client{Transport: tr, Timeout: 5 * time.Second}; req, _ := http.NewRequest("POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(dnsQuery)); req.Header.Set("Content-Type", "application/dns-message"); resp, err := client.Do(req); if err != nil { return nil, err }; defer resp.Body.Close(); return io.ReadAll(resp.Body) }
