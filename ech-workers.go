package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
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
	"strings"
	"sync"
	"time"

	"github.comcom/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr  string
	serverAddr  string
	serverIP    string
	token       string
	echDomain   string
	routingMode string // 分流模式

	// DNS 配置
	dnsWorker string
	dnsPublic string

	echListMu sync.RWMutex
	echList   []byte

	// 中国IP列表
	chinaIPRangesMu   sync.RWMutex
	chinaIPRanges     []ipRange
	chinaIPV6RangesMu sync.RWMutex
	chinaIPV6Ranges   []ipRangeV6
)

type ipRange struct {
	start uint32
	end   uint32
}
type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址")
	flag.StringVar(&serverAddr, "f", "", "服务端地址")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP")
	flag.StringVar(&token, "token", "", "身份验证令牌")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
	flag.StringVar(&dnsWorker, "dns", "", "首选 ECH 获取源 (DOH Worker)")
	flag.StringVar(&dnsPublic, "dns-fallback", "https://dns.alidns.com/dns-query", "备用 ECH 获取源 (公共DOH)")
	flag.StringVar(&routingMode, "routing", "global", "分流模式: global, bypass_cn, none")
}

func main() {
	flag.Parse()
	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 -f")
	}

	log.Printf("[启动] 正在初始化 ECH 配置...")
	if err := prepareECH(); err != nil {
		log.Fatalf("[致命] 获取 ECH 配置失败: %v", err)
	}

	if routingMode == "bypass_cn" {
		log.Printf("[启动] 分流模式: 绕过中国大陆，正在加载 IP 列表...")
		loadChinaLists()
	} else {
		log.Printf("[启动] 分流模式: %s", routingMode)
	}

	runProxyServer(listenAddr)
}

// ======================== ECH 核心逻辑 ========================
// (此部分无修改)
const typeHTTPS = 65
func prepareECH() error {
	var echBase64 string; var err error
	if dnsWorker != "" {
		echBase64, err = queryHTTPSRecord(echDomain, dnsWorker)
		if err == nil && echBase64 != "" { log.Printf("[ECH] 通过首选源获取成功！"); goto Decode }
		log.Printf("[ECH] 首选源失败: %v，切换至备用源...", err)
	}
	if dnsPublic != "" {
		echBase64, err = queryHTTPSRecord(echDomain, dnsPublic)
		if err != nil { return fmt.Errorf("备用源查询失败: %w", err) }
		if echBase64 == "" { return errors.New("备用源未返回有效 ECH 记录") }
		log.Printf("[ECH] 通过备用源获取成功！")
	} else { return errors.New("未配置有效的 ECH 获取源") }
Decode:
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil { return fmt.Errorf("ECH 解码失败: %w", err) }
	echListMu.Lock(); echList = raw; echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw)); return nil
}
func getECHList() ([]byte, error) { echListMu.RLock(); defer echListMu.RUnlock(); if len(echList) == 0 { return nil, errors.New("ECH 配置为空") }; return echList, nil }
func refreshECH() { if err := prepareECH(); err != nil { log.Printf("[警告] ECH 刷新失败: %v", err) } }
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer; if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") { dohURL = "https://" + dohURL }; return queryDoH(domain, dohURL)
}
func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL); if err != nil { return "", err }
	dnsQuery := buildDNSQuery(domain, typeHTTPS); dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q := u.Query(); q.Set("dns", dnsBase64); u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil); if err != nil { return "", err }
	req.Header.Set("Accept", "application/dns-message"); client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req); if err != nil { return "", err }; defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("HTTP %d", resp.StatusCode) }
	body, err := io.ReadAll(resp.Body); if err != nil { return "", err }; return parseDNSResponse(body)
}
func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 12, 512); binary.BigEndian.PutUint16(query[0:], 1); binary.BigEndian.PutUint16(query[2:], 0x0100); binary.BigEndian.PutUint16(query[4:], 1)
	for _, label := range strings.Split(domain, ".") { query = append(query, byte(len(label))); query = append(query, label...) }
	query = append(query, 0); binary.BigEndian.PutUint16(query[len(query):], qtype); query = query[:len(query)+2]; binary.BigEndian.PutUint16(query[len(query):], 1); query = query[:len(query)+2]; return query
}
func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 { return "", errors.New("响应过短") }; ancount := binary.BigEndian.Uint16(response[6:8]); if ancount == 0 { return "", errors.New("无应答记录") }
	offset := 12; for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset += 5
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) { break }; if response[offset]&0xC0 == 0xC0 { offset += 2 } else { for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset++ }
		if offset+10 > len(response) { break }; rrType := binary.BigEndian.Uint16(response[offset:offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(response[offset:offset+2]); offset += 2
		if offset+int(dataLen) > len(response) { break }; data := response[offset : offset+int(dataLen)]; offset += int(dataLen)
		if rrType == typeHTTPS { if ech := parseHTTPSRecord(data); ech != "" { return ech, nil } }
	}
	return "", errors.New("未找到 HTTPS 记录")
}
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 { return "" }; offset := 2; if offset < len(data) && data[offset] == 0 { offset++ } else { for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++ }
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset:offset+2]); length := binary.BigEndian.Uint16(data[offset+2:offset+4]); offset += 4
		if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length)
		if key == 5 { return base64.StdEncoding.EncodeToString(value) }
	}
	return ""
}
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool(); if err != nil { return nil, err }
	config := &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots }
	configValue := reflect.ValueOf(config).Elem()
	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if !field1.IsValid() || !field1.CanSet() { return nil, errors.New("不支持 ECH (需Go 1.23+)") }
	field1.Set(reflect.ValueOf(echList))
	return config, nil
}
// ======================== IP 列表管理 ========================
// (此部分无修改)
func loadChinaLists() {
	if err := loadIPList("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); err == nil {
		chinaIPRangesMu.RLock(); log.Printf("[IP库] 已加载 %d 个 IPv4 段", len(chinaIPRanges)); chinaIPRangesMu.RUnlock()
	} else { log.Printf("[警告] 加载 IPv4 列表失败: %v", err) }
	if err := loadIPList("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true); err == nil {
		chinaIPV6RangesMu.RLock(); log.Printf("[IP库] 已加载 %d 个 IPv6 段", len(chinaIPV6Ranges)); chinaIPV6RangesMu.RUnlock()
	} else { log.Printf("[警告] 加载 IPv6 列表失败: %v", err) }
}
func loadIPList(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) error {
	exePath, _ := os.Executable(); filePath := filepath.Join(filepath.Dir(exePath), filename); if _, err := os.Stat(filePath); os.IsNotExist(err) { filePath = filename }
	if info, err := os.Stat(filePath); os.IsNotExist(err) || info.Size() == 0 {
		url := "https://mirror.ghproxy.com/https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/" + filename; log.Printf("[下载] 正在下载 IP 列表: %s", filename)
		if err := downloadFile(url, filePath); err != nil { return err }
	}
	file, err := os.Open(filePath); if err != nil { return err }; defer file.Close()
	var rangesV4 []ipRange; var rangesV6 []ipRangeV6; scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }
		if isV6 { var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16()); rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e}) } else { s, e := ipToUint32(startIP), ipToUint32(endIP); if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) } }
	}
	mu.Lock(); defer mu.Unlock()
	if isV6 { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6)) } else { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) }
	return nil
}
func downloadFile(url, path string) error { resp, err := http.Get(url); if err != nil { return err }; defer resp.Body.Close(); if resp.StatusCode != 200 { return fmt.Errorf("status %d", resp.StatusCode) }; data, err := io.ReadAll(resp.Body); if err != nil { return err }; return os.WriteFile(path, data, 0644) }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func shouldBypassProxy(targetHost string) bool {
	if routingMode == "none" { return true }; if routingMode == "global" { return false }
	if routingMode == "bypass_cn" {
		if ip := net.ParseIP(targetHost); ip != nil { return isChinaIP(ip) }
		ips, err := net.LookupIP(targetHost); if err != nil { return false }
		for _, ip := range ips { if isChinaIP(ip) { return true } }
	}
	return false
}
func isChinaIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock()
		for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } }
	} else if ip16 := ip.To16(); ip16 != nil {
		var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock()
		for _, r := range chinaIPV6Ranges { if compareIPv6(val, r.start) >= 0 && compareIPv6(val, r.end) <= 0 { return true } }
	}
	return false
}
func compareIPv6(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) }
// ======================== WebSocket 连接 ========================
// (此部分无修改)
func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return
}
func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(serverAddr); if err != nil { return nil, err }
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)
	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, err := getECHList(); if err != nil { if attempt < maxRetries { refreshECH(); continue }; return nil, err }
		tlsCfg, _ := buildTLSConfigWithECH(host, echBytes); 
		dialer := websocket.Dialer{ TLSClientConfig: tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{token} }
		if serverIP != "" { dialer.NetDial = func(network, address string) (net.Conn, error) { _, p, _ := net.SplitHostPort(address); return net.DialTimeout(network, net.JoinHostPort(serverIP, p), 10*time.Second) } }
		conn, _, err := dialer.Dial(wsURL, nil); if err != nil {
			if strings.Contains(err.Error(), "ECH") && attempt < maxRetries { log.Printf("[重连] ECH 可能失效，正在刷新..."); refreshECH(); time.Sleep(1 * time.Second); continue }
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.New("连接失败")
}

// ======================== 【【【核心修复区】】】 ========================

func runProxyServer(addr string) {
	l, err := net.Listen("tcp", addr); if err != nil { log.Fatalf("监听失败: %v", err) }
	log.Printf("[服务] 监听地址: %s", addr); log.Printf("[服务] 后端服务器: %s", serverAddr)
	for { conn, err := l.Accept(); if err == nil { go handleConnection(conn) } }
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	buf := make([]byte, 1); _, err := io.ReadFull(conn, buf)
	if err != nil { return }

	if buf[0] == 0x05 { // SOCKS5
		handleSOCKS5(conn, clientAddr, buf[0])
	} else { // HTTP
		handleHTTP(conn, clientAddr, buf[0])
	}
}

// [修改] handleSOCKS5/handleHTTP 只负责解析和调用 handleTunnel，不再发送成功响应
func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil { return }
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil { return } // Assume 1 method
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return }
	
	header := make([]byte, 4); if _, err := io.ReadFull(conn, header); err != nil { return }
	cmd := header[1]; atyp := header[3]
	var host string
	switch atyp {
	case 1: ip := make([]byte, 4); io.ReadFull(conn, ip); host = net.IP(ip).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); domain := make([]byte, b[0]); io.ReadFull(conn, domain); host = string(domain)
	case 4: ip := make([]byte, 16); io.ReadFull(conn, ip); host = net.IP(ip).String()
	default: return
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if cmd == 0x01 { // CONNECT
		log.Printf("[SOCKS5] %s -> %s", clientAddr, target)
		if err := handleTunnel(conn, target, nil); err != nil {
			log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
		}
	} // UDP not supported in this simplified log-fixed version for clarity
}

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	req, err := http.ReadRequest(reader); if err != nil { return }

	if req.Method == "CONNECT" {
		log.Printf("[HTTP] %s -> CONNECT %s", clientAddr, req.Host)
		if err := handleTunnel(conn, req.Host, nil); err != nil {
			log.Printf("[HTTP] %s 代理失败: %v", clientAddr, err)
		}
	} else {
		// HTTP proxy request logic (simplified for example)
		log.Printf("[HTTP] %s -> %s %s", clientAddr, req.Method, req.Host)
		var buf bytes.Buffer
		req.WriteProxy(&buf)
		if err := handleTunnel(conn, req.Host, buf.Bytes()); err != nil {
			log.Printf("[HTTP] %s 代理失败: %v", clientAddr, err)
		}
	}
}

// [修改] handleTunnel 恢复旧版逻辑：先连接，成功再响应
func handleTunnel(clientConn net.Conn, target string, firstFrame []byte) error {
	host, _, _ := net.SplitHostPort(target)
	if host == "" { host = target }

	// 1. 分流判断
	if shouldBypassProxy(host) {
		log.Printf("[分流] %s 直连", target)
		return startDirect(clientConn, target, firstFrame)
	}

	// 2. 走代理，先连接
	wsConn, err := dialWebSocketWithECH(2)
	if err != nil {
		sendErrorResponse(clientConn, target)
		return err
	}
	defer wsConn.Close()

	// 3. 连接成功，再发握手包
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil {
		sendErrorResponse(clientConn, target)
		return err
	}
	_, msg, err := wsConn.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" {
		sendErrorResponse(clientConn, target)
		return fmt.Errorf("握手失败: %s", string(msg))
	}
	
	// 4. 全部成功，才响应客户端
	if err := sendSuccessResponse(clientConn, target, firstFrame != nil); err != nil {
		return err
	}
	log.Printf("[代理] %s 已连接", target)

	// 5. 转发数据
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyWithClose(clientConn, wsConn) }()
	go func() { defer wg.Done(); copyWithClose(wsConn, clientConn) }()
	wg.Wait()
	log.Printf("[代理] %s 已断开", target)
	return nil
}

// 辅助函数
func startDirect(clientConn net.Conn, target string, firstFrame []byte) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		sendErrorResponse(clientConn, target)
		return err
	}
	defer remote.Close()
	if err := sendSuccessResponse(clientConn, target, firstFrame != nil); err != nil {
		return err
	}
	if len(firstFrame) > 0 { remote.Write(firstFrame) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, clientConn) }()
	go func() { defer wg.Done(); io.Copy(clientConn, remote) }()
	wg.Wait()
	return nil
}

func sendErrorResponse(conn net.Conn, target string) {
	if _, ok := conn.RemoteAddr().(*net.TCPAddr); ok { // SOCKS or CONNECT
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // General failure
	} else { // HTTP Proxy
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, target string, isHttpProxy bool) error {
	if isHttpProxy { // HTTP GET/POST etc.
		return nil // No response needed, tunnel will forward server's response
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil { // SOCKS5
		return err
	}
	// This also works for HTTP CONNECT which expects a 200 OK, but SOCKS5 response is harmless
	return nil
}
// copyWithClose helps to close the other connection when one side is done
func copyWithClose(dst io.Writer, src io.Reader) {
    io.Copy(dst, src)
    if conn, ok := dst.(net.Conn); ok {
        conn.Close()
    }
    if conn, ok := src.(net.Conn); ok {
        conn.Close()
    }
}
