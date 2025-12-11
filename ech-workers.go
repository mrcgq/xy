// ech-workers.go — Minimal, fixed and self-contained implementation
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/gorilla/websocket"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/app/router"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/infra/conf/geodata"
	"github.com/v2fly/v2ray-core/v5/infra/conf/geodata/standard"
)

//go:embed geoip.dat
var geoipBytes []byte

//go:embed geosite.dat
var geositeBytes []byte

var (
	listenAddr  string
	serverAddr  string
	serverIP    string
	token       string
	dnsPrimary  string
	dnsFallback string
	echDomain   string

	echListMu sync.RWMutex
	echList   []byte

	routerInstance routing.Router
)

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址")
	flag.StringVar(&serverAddr, "f", "", "服务端地址，格式 host:port 或 host:port/path")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP（可选）")
	flag.StringVar(&token, "token", "", "身份验证令牌（可选）")
	flag.StringVar(&dnsPrimary, "dns", "", "首选的 DoH 地址（可选）")
	flag.StringVar(&dnsFallback, "dns-fallback", "https://dns.alidns.com/dns-query", "备用 DoH 地址")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "用于查询 ECH 的域名")
}

// initRouter sets up v2ray-core router using embedded geoip/geosite data.
func initRouter() error {
	if len(geoipBytes) == 0 || len(geositeBytes) == 0 {
		return errors.New("嵌入的路由规则文件为空 (geoip.dat / geosite.dat)")
	}

	loader, err := standard.NewBytesLoader(geoipBytes, geositeBytes)
	if err != nil {
		return fmt.Errorf("创建 geodata 加载器失败: %w", err)
	}
	geodata.SetService(loader)

	cfg := &router.Config{
		DomainStrategy: router.DomainStrategy_IpIfNonMatch,
		Rule: []*router.RoutingRule{
			{
				Geoip:     []*router.GeoIP{{Code: "cn"}},
				TargetTag: &router.RouteTarget{Tag: "direct"},
			},
			{
				Domain:    []*router.Domain{{Type: router.Domain_Geosite, Value: "cn"}},
				TargetTag: &router.RouteTarget{Tag: "direct"},
			},
		},
	}

	// core.CreateObject(nil, cfg) - nil instance is acceptable in this usage for object creation
	rObj, err := core.CreateObject(nil, cfg)
	if err != nil {
		return fmt.Errorf("创建 v5 路由引擎失败: %w", err)
	}
	routerInstance = rObj.(routing.Router)
	log.Println("[路由] v5 嵌入式路由引擎初始化成功，已加载 CN 分流规则")
	return nil
}

// shouldProxy checks if target should go through proxy (not direct)
func shouldProxy(target string) bool {
	if routerInstance == nil {
		return true
	}
	host, portStr, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}
	port, _ := v2net.PortFromString(portStr)
	if port == 0 {
		port = 80
	}

	var dest v2net.Destination
	ip := net.ParseIP(host)
	if ip != nil {
		dest = v2net.UDPDestination(v2net.IPAddress(ip), port)
	} else {
		dest = v2net.UDPDestination(v2net.DomainAddress(host), port)
	}

	ctx := routing.ContextWithDestination(context.Background(), dest)
	route, err := routerInstance.PickRoute(ctx)
	if err != nil {
		return true
	}
	return route.GetTag() != "direct"
}

func pipeConnections(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
	}()
	wg.Wait()
}

func main() {
	flag.Parse()
	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 (-f)")
	}

	if err := initRouter(); err != nil {
		log.Printf("[路由] 警告: %v", err)
		log.Println("[路由] 未能初始化嵌入式路由，所有流量将默认代理")
	}

	log.Println("[启动] 尝试获取 ECH（如果可用）...")
	if err := prepareECH(); err != nil {
		log.Printf("[ECH] 获取失败：%v（继续运行，回退到普通 TLS）", err)
	} else {
		log.Printf("[ECH] ECH 数据已加载（%d 字节）", len(echList))
	}

	runProxyServer(listenAddr)
}

// runProxyServer starts TCP server that accepts SOCKS5 and HTTP proxy connections.
func runProxyServer(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[代理] 监听失败: %v", err)
	}
	defer l.Close()
	log.Printf("[代理] 监听 %s (支持 SOCKS5/HTTP)", addr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[代理] Accept 错误: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	client := conn.RemoteAddr().String()
	_ = client
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, 1)
	n, err := conn.Read(b)
	if err != nil || n == 0 {
		return
	}
	conn.SetDeadline(time.Time{})
	first := b[0]
	switch first {
	case 0x05:
		handleSOCKS5(conn, conn.RemoteAddr().String(), first)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		handleHTTP(conn, conn.RemoteAddr().String(), first)
	default:
		log.Printf("[代理] 未知协议首字节 0x%02x 来自 %s", first, conn.RemoteAddr().String())
	}
}

// ----------------------- SOCKS5 处理 -----------------------
func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	// basic socks5 handshake + CONNECT support
	if firstByte != 0x05 {
		return
	}
	// 方法协商
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	nmethods := int(buf[0])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// 不使用认证
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 请求
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	cmd := header[1]
	atyp := header[3]
	var host string
	switch atyp {
	case 0x01:
		ipb := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipb); err != nil {
			return
		}
		host = net.IP(ipb).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return
		}
		domain := make([]byte, lb[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04:
		ipb := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipb); err != nil {
			return
		}
		host = net.IP(ipb).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	target := host
	if !strings.Contains(host, ":") {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	if cmd != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if !shouldProxy(target) {
		log.Printf("[分流] SOCKS5 直连 -> %s", target)
		dst, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		pipeConnections(conn, dst)
		return
	}

	log.Printf("[分流] SOCKS5 代理 -> %s", target)
	if err := handleTunnel(conn, target, clientAddr, 1, nil); err != nil {
		if !isNormalCloseError(err) {
			log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
		}
	}
}

// ----------------------- HTTP 处理 -----------------------
func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn))
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}
	method := parts[0]
	requestURL := parts[1]
	httpVersion := parts[2]

	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = val
		}
	}

	switch method {
	case "CONNECT":
		target := requestURL
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		if !shouldProxy(target) {
			log.Printf("[分流] CONNECT 直连 -> %s", target)
			dst, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				return
			}
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			pipeConnections(conn, dst)
			return
		}
		log.Printf("[分流] CONNECT 代理 -> %s", target)
		if err := handleTunnel(conn, target, clientAddr, 2, nil); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-CONNECT] %s 代理失败: %v", clientAddr, err)
			}
		}
	default:
		// 普通 http 请求 (GET/POST...)
		var target string
		var path string
		if strings.HasPrefix(requestURL, "http://") || strings.HasPrefix(requestURL, "https://") {
			u, err := url.Parse(requestURL)
			if err != nil {
				conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				return
			}
			target = u.Host
			path = u.RequestURI()
		} else {
			target = headers["host"]
			path = requestURL
		}
		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		if !strings.Contains(target, ":") {
			target += ":80"
		}
		var bld strings.Builder
		bld.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))
		for _, line := range headerLines {
			k := strings.SplitN(line, ":", 2)[0]
			if strings.ToLower(strings.TrimSpace(k)) == "proxy-connection" || strings.ToLower(strings.TrimSpace(k)) == "proxy-authorization" {
				continue
			}
			bld.WriteString(line + "\r\n")
		}
		bld.WriteString("\r\n")
		if cl, ok := headers["content-length"]; ok {
			var length int
			fmt.Sscanf(cl, "%d", &length)
			if length > 0 && length < 10*1024*1024 {
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					bld.Write(body)
				}
			}
		}
		firstFrame := []byte(bld.String())
		if err := handleTunnel(conn, target, clientAddr, 3, firstFrame); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-%s] %s 代理失败: %v", method, clientAddr, err)
			}
		}
	}
}

// ----------------------- Tunnel via WebSocket -----------------------

func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame []byte) error {
	// 建立到后端的 WebSocket 连接（可选使用 ECH）
	wsConn, err := dialWebSocketWithECH(10)
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer wsConn.Close()

	// ping 保持
	var mu sync.Mutex
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.PingMessage, nil)
				mu.Unlock()
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)

	// 如果 firstFrame 为空并且来源是 TCP (SOCKS5)，尝试读一点数据作为初始 payload
	if firstFrame == nil && mode == 1 {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 32*1024)
		n, _ := conn.Read(buf)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 {
			firstFrame = buf[:n]
		}
	}

	encoded := ""
	if len(firstFrame) > 0 {
		encoded = base64.StdEncoding.EncodeToString(firstFrame)
	}

	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, encoded)
	mu.Lock()
	err = wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg))
	mu.Unlock()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	// 读取 backend 的确认消息
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	resp := string(msg)
	if strings.HasPrefix(resp, "ERROR:") {
		sendErrorResponse(conn, mode)
		return errors.New(resp)
	}
	if resp != "CONNECTED" {
		sendErrorResponse(conn, mode)
		return fmt.Errorf("意外响应: %s", resp)
	}

	// 成功，向客户端返回相应的 CONNECT OK
	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}
	log.Printf("[代理] %s 已连接: %s", clientAddr, target)

	// 双向转发：客户端 TCP <-> websocket binary frames
	done := make(chan struct{}, 2)
	// client -> websocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				return
			}
			mu.Lock()
			err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	// websocket -> client
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			mt, msg, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage {
				if string(msg) == "CLOSE" {
					return
				}
				// ignore other control text messages
				continue
			}
			if _, err := conn.Write(msg); err != nil {
				return
			}
		}
	}()

	<-done
	log.Printf("[代理] %s 已断开: %s", clientAddr, target)
	return nil
}

// sendErrorResponse 写回客户端错误响应
func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case 1:
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	case 2, 3:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	default:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

// sendSuccessResponse 对不同模式返回成功响应
func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case 1:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	case 2:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	case 3:
		return nil
	}
	return nil
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "normal closure")
}

// ----------------------- ECH / DoH helpers -----------------------

// prepareECH tries multiple DoH endpoints (dnsPrimary first if provided, then dnsFallback)
// It will populate echList (raw bytes) if a valid HTTPS record containing ECH is found.
// Note: Go standard library currently doesn't provide a stable public API to set ECH bytes in tls.Config.
// We still fetch and store the bytes for future usage in custom TLS stacks.
func prepareECH() error {
	var encoded string
	var err error
	if dnsPrimary != "" {
		log.Printf("[ECH] 尝试通过首选 DoH(%s) 查询 %s ...", dnsPrimary, echDomain)
		encoded, err = queryHTTPSRecord(echDomain, dnsPrimary)
		if err == nil && encoded != "" {
			goto Decode
		}
		log.Printf("[ECH] 首选 DoH 失败: %v", err)
	}
	if dnsFallback != "" {
		log.Printf("[ECH] 尝试通过备用 DoH(%s) 查询 %s ...", dnsFallback, echDomain)
		encoded, err = queryHTTPSRecord(echDomain, dnsFallback)
		if err != nil {
			return fmt.Errorf("备用 DoH 失败: %w", err)
		}
		if encoded == "" {
			return errors.New("DoH 未返回 HTTPS 记录")
		}
	} else {
		return errors.New("无可用 DoH")
	}

Decode:
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("解码 ECH 数据失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	return nil
}

// queryHTTPSRecord uses DoH URL (must be full URL) to query DNS wire-format with type HTTPS (65)
// Returns base64.StdEncoding string of the value that we interpret as ECH bytes (implementation-specific)
func queryHTTPSRecord(domain, dohURL string) (string, error) {
	u := dohURL
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + dohURL
	}
	return queryDoH(domain, u)
}

const typeHTTPS = 65

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效 DoH URL: %v", err)
	}
	q := buildDNSQuery(domain, typeHTTPS)
	// Use rawurl encoding without padding for GET parameter
	dnsb := base64.RawURLEncoding.EncodeToString(q)
	v := u.Query()
	v.Set("dns", dnsb)
	u.RawQuery = v.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("DoH 返回状态: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	// Simple DNS query builder (no EDNS)
	out := make([]byte, 12)
	// id
	out[0] = 0
	out[1] = 1
	// flags: standard query
	out[2] = 0
	out[3] = 0
	// qdcount = 1
	out[4] = 0
	out[5] = 1
	out[6] = 0
	out[7] = 0
	out[8] = 0
	out[9] = 0
	out[10] = 0
	out[11] = 0

	for _, lab := range strings.Split(domain, ".") {
		out = append(out, byte(len(lab)))
		out = append(out, []byte(lab)...)
	}
	out = append(out, 0)
	out = append(out, byte(qtype>>8), byte(qtype&0xff))
	// class IN
	out = append(out, 0x00, 0x01)
	return out
}

// parseDNSResponse scans the answer section to find HTTPS (type 65) and extract an ECH-like value
func parseDNSResponse(resp []byte) (string, error) {
	if len(resp) < 12 {
		return "", errors.New("DNS 响应过短")
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	// skip question section
	offset := 12
	for offset < len(resp) && resp[offset] != 0 {
		offset += int(resp[offset]) + 1
	}
	offset += 5 // null + qtype + qclass
	for i := 0; i < ancount && offset < len(resp); i++ {
		// skip name (could be pointer)
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(resp) && resp[offset] != 0 {
				offset += int(resp[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(resp) {
			break
		}
		rrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		offset += 8
		dataLen := int(binary.BigEndian.Uint16(resp[offset : offset+2]))
		offset += 2
		if offset+dataLen > len(resp) {
			break
		}
		data := resp[offset : offset+dataLen]
		offset += dataLen
		if rrType == typeHTTPS {
			// try parse HTTPS record to find key=5 (ECH) - parse with simple TLV loop
			if s := parseHTTPSRecord(data); s != "" {
				return s, nil
			}
		}
	}
	return "", errors.New("未在 DNS 响应中找到 HTTPS/ECH")
}

func parseHTTPSRecord(data []byte) string {
	// RFC values vary; here we try simple parse: skip alpn/priority fields then parse key/len TLVs.
	if len(data) < 2 {
		return ""
	}
	// Try to find key=5 in the subsequent TLVs
	// Skip first 2 bytes (priority) and optional SVCB name (a sequence of labels)
	offset := 0
	// Skip priority (2 bytes)
	if offset+2 > len(data) {
		return ""
	}
	offset += 2
	// If next is 0, that's empty name
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	// Now parse key-length pairs
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			// Return base64 encoding so callers can decode into raw bytes
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 未加载")
	}
	return echList, nil
}

// buildTLSConfigWithECH returns a tls.Config; note: standard library currently doesn't expose a safe API for raw ECH bytes.
// This function will return a normal tls.Config (ServerName + system roots). We keep the echBytes parameter for future extension.
func buildTLSConfigWithECH(serverName string, echBytes []byte) (*tls.Config, error) {
	roots, _ := x509.SystemCertPool()
	// we cannot set ECH in crypto/tls (stable) here; return a normal config but record we have ECH bytes (unused)
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	// Log that we have echBytes (for debug)
	if len(echBytes) > 0 {
		log.Printf("[ECH] 准备连接 %s，已获取 ECH (%d 字节) —— 标记为可用（注意：当前 tls.Config 未直接注入 ECH）", serverName, len(echBytes))
	}
	return cfg, nil
}

// dialWebSocketWithECH establishes a wss websocket to serverAddr (path optional).
func dialWebSocketWithECH(timeoutSec int) (*websocket.Conn, error) {
	if serverAddr == "" {
		return nil, errors.New("未设置 serverAddr (-f)")
	}
	host, _, path, err := parseServerAddr(serverAddr)
	if err != nil {
		// try parse as URL
		u, err2 := url.Parse(serverAddr)
		if err2 == nil && u.Host != "" {
			host = u.Host
			path = u.Path
		} else {
			return nil, fmt.Errorf("无法解析 serverAddr: %v", err)
		}
	}
	// Try to get ECH bytes (may be empty)
	echBytes, _ := getECHList()
	// Build TLS config (currently ECH bytes are informational)
	tlsCfg, err := buildTLSConfigWithECH(host, echBytes)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: time.Duration(timeoutSec) * time.Second,
		TLSClientConfig:  tlsCfg,
	}
	u := url.URL{Scheme: "wss", Host: host, Path: path}
	header := http.Header{}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	ws, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		if resp != nil {
			log.Printf("[WS] 连接 %s 返回状态: %s", u.String(), resp.Status)
		}
		return nil, err
	}
	return ws, nil
}

// parseServerAddr accepts "host:port/path" or "host:port" and returns host, port, path
func parseServerAddr(addr string) (string, string, string, error) {
	path := "/"
	orig := addr
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", "", fmt.Errorf("服务器地址应为 host:port 或 host:port/path （原始: %s）: %v", orig, err)
	}
	return host + ":" + port, port, path, nil
}
