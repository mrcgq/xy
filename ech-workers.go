// ech-workers.exe 内核代码 (最终智能分流单文件版 - 内嵌路由规则)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed" // 1. 引入 embed 包
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
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	
	"github.com/v2fly/v2ray-core/v5/app/router"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/infra/conf/geodata"
	core "github.com/v2fly/v2ray-core/v5"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
)

// 2. 使用 //go:embed 指令嵌入文件
//go:embed geoip.dat
var geoipBytes []byte

//go:embed geosite.dat
var geositeBytes []byte

// 3. 自定义一个从内存加载规则的加载器
type memoryLoader struct{}
func (l *memoryLoader) LoadGeoIP(country string) (*router.GeoIP, error) {
	return router.LoadGeoIP(bytes.NewReader(geoipBytes))
}
func (l *memoryLoader) LoadGeosite(list string) (*router.GeoSite, error) {
	return router.LoadGeosite(bytes.NewReader(geositeBytes))
}

// (全局变量保持不变)
var (
	listenAddr   string; serverAddr   string; serverIP     string; token        string
	dnsPrimary   string; dnsFallback  string; echDomain    string; echListMu    sync.RWMutex
	echList      []byte; routerInstance routing.Router
)

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址")
	flag.StringVar(&serverAddr, "f", "", "服务端地址")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP")
	flag.StringVar(&token, "token", "", "身份验证令牌")
	flag.StringVar(&dnsPrimary, "dns", "", "首选的 DOH 代理 Worker 地址")
	flag.StringVar(&dnsFallback, "dns-fallback", "https://dns.alidns.com/dns-query", "备用的公共 DOH 服务器地址")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
}

// 4. 修改 initRouter 函数，使用我们的自定义加载器
func initRouter() error {
	if len(geoipBytes) == 0 || len(geositeBytes) == 0 {
		return errors.New("嵌入的路由规则文件为空，请在编译时确保 geoip.dat 和 geosite.dat 在同目录下")
	}

	// 使用我们自定义的内存加载器，不再需要从磁盘读取
	geodata.DefaultLoader = &memoryLoader{}

	config := &router.Config{
		DomainStrategy: router.DomainStrategy_IpIfNonMatch,
		Rule: []*router.RoutingRule{
			{ Geoip: []*router.GeoIP{{Code: "cn"}}, TargetTag: &router.RouteTarget{Tag: "direct"}},
			{ Geosite: []*router.Geosite{{Code: "cn"}}, TargetTag: &router.RouteTarget{Tag: "direct"}},
		},
	}
	
	r, err := core.CreateObject(context.Background(), config)
	if err != nil { return fmt.Errorf("创建路由引擎失败: %w", err) }
	
	routerInstance = r.(routing.Router)
	log.Println("[路由] v5 嵌入式路由引擎初始化成功，已加载 CN 分流规则")
	return nil
}

// (shouldProxy, pipeConnections, main 和所有后续 ECH/WebSocket 代码与上一版完全相同，无需修改)
func shouldProxy(target string) bool { if routerInstance == nil { return true }; host, portStr, _ := net.SplitHostPort(target); if host == "" { host = target }; port, _ := v2net.PortFromString(portStr); if port == 0 { port = 80 }; var dest v2net.Destination; ip := net.ParseIP(host); if ip != nil { dest = v2net.UDPDestination(v2net.IPAddress(ip), port) } else { dest = v2net.UDPDestination(v2net.DomainAddress(host), port) }; ctx := routing.ContextWithDestination(context.Background(), dest); route, err := routerInstance.PickRoute(ctx); if err != nil { return true }; return route.GetTag() != "direct" }
func pipeConnections(client, target net.Conn) { defer client.Close(); defer target.Close(); var wg sync.WaitGroup; wg.Add(2); go func() { defer wg.Done(); io.Copy(target, client) }(); go func() { defer wg.Done(); io.Copy(client, target) }(); wg.Wait() }

func main() {
	flag.Parse(); if serverAddr == "" { log.Fatal("必须指定服务端地址 -f") }
	if err := initRouter(); err != nil { log.Printf("[路由] 警告: %v", err); log.Printf("[路由] 所有流量将默认通过代理。") }
	log.Printf("[启动] 正在获取 ECH 配置 (双轨模式)..."); if err := prepareECH(); err != nil { log.Fatalf("[启动] 所有 ECH 配置获取方式均失败: %v", err) }
	runProxyServer(listenAddr)
}

func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) { if firstByte != 0x05 { return }; buf := make([]byte, 1); if _, err := io.ReadFull(conn, buf); err != nil { return }; nmethods := buf[0]; methods := make([]byte, nmethods); if _, err := io.ReadFull(conn, methods); err != nil { return }; if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return }; buf = make([]byte, 4); if _, err := io.ReadFull(conn, buf); err != nil { return }; if buf[0] != 5 { return }; command := buf[1]; atyp := buf[3]; var host string; switch atyp { case 0x01: buf = make([]byte, 4); if _, err := io.ReadFull(conn, buf); err != nil { return }; host = net.IP(buf).String(); case 0x03: buf = make([]byte, 1); if _, err := io.ReadFull(conn, buf); err != nil { return }; domainBuf := make([]byte, buf[0]); if _, err := io.ReadFull(conn, domainBuf); err != nil { return }; host = string(domainBuf); case 0x04: buf = make([]byte, 16); if _, err := io.ReadFull(conn, buf); err != nil { return }; host = net.IP(buf).String(); default: conn.Write([]byte{0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0}); return }; buf = make([]byte, 2); if _, err := io.ReadFull(conn, buf); err != nil { return }; port := int(buf[0])<<8 | int(buf[1]); var target string; if atyp == 0x04 { target = fmt.Sprintf("[%s]:%d", host, port) } else { target = fmt.Sprintf("%s:%d", host, port) }; if command != 0x01 { conn.Write([]byte{0x05, 0x07, 0, 1, 0, 0, 0, 0, 0, 0}); return }; if !shouldProxy(target) { log.Printf("[分流] SOCKS5 直连 -> %s", target); targetConn, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { conn.Write([]byte{0x05, 0x04, 0, 1, 0, 0, 0, 0, 0, 0}); return }; defer targetConn.Close(); conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0}); pipeConnections(conn, targetConn); return }; log.Printf("[分流] SOCKS5 代理 -> %s", target); if err := handleTunnel(conn, target, clientAddr, 1, nil); err != nil { if !isNormalCloseError(err) { log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err) } } }
func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) { reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn)); requestLine, err := reader.ReadString('\n'); if err != nil { return }; parts := strings.Fields(requestLine); if len(parts) < 3 { return }; method, requestURL, httpVersion := parts[0], parts[1], parts[2]; headers := make(map[string]string); var headerLines []string; for { line, err := reader.ReadString('\n'); if err != nil { return }; line = strings.TrimRight(line, "\r\n"); if line == "" { break }; headerLines = append(headerLines, line); if idx := strings.Index(line, ":"); idx > 0 { key := strings.TrimSpace(line[:idx]); value := strings.TrimSpace(line[idx+1:]); headers[strings.ToLower(key)] = value } }; switch method { case "CONNECT": target := requestURL; if !strings.Contains(target, ":") { target += ":443" }; if !shouldProxy(target) { log.Printf("[分流] CONNECT 直连 -> %s", target); targetConn, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); return }; defer targetConn.Close(); conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); pipeConnections(conn, targetConn); return }; log.Printf("[分流] CONNECT 代理 -> %s", target); if err := handleTunnel(conn, target, clientAddr, 2, nil); err != nil { if !isNormalCloseError(err) { log.Printf("[HTTP-CONNECT] %s 代理失败: %v", clientAddr, err) } }; case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE": log.Printf("[HTTP-%s] %s -> %s", method, clientAddr, requestURL); var target string; var path string; if strings.HasPrefix(requestURL, "http://") { urlWithoutScheme := strings.TrimPrefix(requestURL, "http://"); idx := strings.Index(urlWithoutScheme, "/"); if idx > 0 { target = urlWithoutScheme[:idx]; path = urlWithoutScheme[idx:] } else { target = urlWithoutScheme; path = "/" } } else { target = headers["host"]; path = requestURL }; if target == "" { conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); return }; if !strings.Contains(target, ":") { target += ":80" }; var requestBuilder strings.Builder; requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion)); for _, line := range headerLines { key := strings.Split(line, ":")[0]; keyLower := strings.ToLower(strings.TrimSpace(key)); if keyLower != "proxy-connection" && keyLower != "proxy-authorization" { requestBuilder.WriteString(line); requestBuilder.WriteString("\r\n") } }; requestBuilder.WriteString("\r\n"); if contentLength := headers["content-length"]; contentLength != "" { var length int; fmt.Sscanf(contentLength, "%d", &length); if length > 0 && length < 10*1024*1024 { body := make([]byte, length); if _, err := io.ReadFull(reader, body); err == nil { requestBuilder.Write(body) } } }; firstFrame := requestBuilder.String(); if err := handleTunnel(conn, target, clientAddr, 3, []byte(firstFrame)); err != nil { if !isNormalCloseError(err) { log.Printf("[HTTP-%s] %s 代理失败: %v", method, clientAddr, err) } }; default: conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n")) } }
func prepareECH() error { var echBase64 string; var err error; if dnsPrimary != "" { log.Printf("[启动] 正在通过首选 DOH 代理 [%s] 获取...", dnsPrimary); echBase64, err = queryHTTPSRecord(echDomain, dnsPrimary); if err == nil && echBase64 != "" { log.Printf("[启动] 通过 DOH 代理 Worker 成功获取！"); goto DecodeECH }; log.Printf("[警告] 通过首选 DOH 代理失败: %v。正在尝试备用方案...", err) }; if dnsFallback != "" { log.Printf("[启动] 正在通过备用公共 DOH [%s] 获取...", dnsFallback); echBase64, err = queryHTTPSRecord(echDomain, dnsFallback); if err != nil { return fmt.Errorf("备用公共 DOH 方案也失败了: %w", err) }; if echBase64 == "" { return errors.New("通过备用公共 DOH 未找到 ECH 参数") }; log.Printf("[启动] 通过备用公共 DOH 成功获取！") } else { return errors.New("没有配置任何有效的 ECH 配置获取方式 (dns 或 dns-fallback)") }; DecodeECH: raw, err := base64.StdEncoding.DecodeString(echBase64); if err != nil { return fmt.Errorf("ECH 配置解码失败: %w", err) }; echListMu.Lock(); echList = raw; echListMu.Unlock(); log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw)); return nil }
const typeHTTPS = 65
func isNormalCloseError(err error) bool { if err == nil { return false }; if err == io.EOF { return true }; errStr := err.Error(); return strings.Contains(errStr, "use of closed network connection") || strings.Contains(errStr, "broken pipe") || strings.Contains(errStr, "connection reset by peer") || strings.Contains(errStr, "normal closure") }
func getECHList() ([]byte, error) { echListMu.RLock(); defer echListMu.RUnlock(); if len(echList) == 0 { return nil, errors.New("ECH 配置未加载") }; return echList, nil }
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) { roots, err := x509.SystemCertPool(); if err != nil { return nil, fmt.Errorf("加载系统根证书失败: %w", err) }; return &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: serverName, EncryptedClientHelloConfigList: echList, EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error { return errors.New("服务器拒绝 ECH") }, RootCAs: roots, }, nil }
func queryHTTPSRecord(domain, dnsServer string) (string, error) { dohURL := dnsServer; if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") { dohURL = "https://" + dohURL }; return queryDoH(domain, dohURL) }
func queryDoH(domain, dohURL string) (string, error) { u, err := url.Parse(dohURL); if err != nil { return "", fmt.Errorf("无效的 DoH URL: %v", err) }; dnsQuery := buildDNSQuery(domain, typeHTTPS); dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery); q := u.Query(); q.Set("dns", dnsBase64); u.RawQuery = q.Encode(); req, err := http.NewRequest("GET", u.String(), nil); if err != nil { return "", fmt.Errorf("创建请求失败: %v", err) }; req.Header.Set("Accept", "application/dns-message"); req.Header.Set("Content-Type", "application/dns-message"); client := &http.Client{Timeout: 10 * time.Second}; resp, err := client.Do(req); if err != nil { return "", fmt.Errorf("DoH 请求失败: %w", err) }; defer resp.Body.Close(); if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode) }; body, err := io.ReadAll(resp.Body); if err != nil { return "", fmt.Errorf("读取 DoH 响应失败: %v", err) }; return parseDNSResponse(body) }
func buildDNSQuery(domain string, qtype uint16) []byte { query := make([]byte, 0, 512); query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00); for _, label := range strings.Split(domain, ".") { query = append(query, byte(len(label))); query = append(query, []byte(label)...) }; query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01); return query }
func parseDNSResponse(response []byte) (string, error) { if len(response) < 12 { return "", errors.New("响应过短") }; ancount := binary.BigEndian.Uint16(response[6:8]); if ancount == 0 { return "", errors.New("无应答记录") }; offset := 12; for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset += 5; for i := 0; i < int(ancount); i++ { if offset >= len(response) { break }; if response[offset]&0xC0 == 0xC0 { offset += 2 } else { for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset++ }; if offset+10 > len(response) { break }; rrType := binary.BigEndian.Uint16(response[offset : offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(response[offset : offset+2]); offset += 2; if offset+int(dataLen) > len(response) { break }; data := response[offset : offset+int(dataLen)]; offset += int(dataLen); if rrType == typeHTTPS { if ech := parseHTTPSRecord(data); ech != "" { return ech, nil } } }; return "", errors.New("在DNS响应中未找到HTTPS记录") }
func parseHTTPSRecord(data []byte) string { if len(data) < 2 { return "" }; offset := 2; if offset < len(data) && data[offset] == 0 { offset++ } else { for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++ }; for offset+4 <= len(data) { key := binary.BigEndian.Uint16(data[offset : offset+2]); length := binary.BigEndian.Uint16(data[offset+2 : offset+4]); offset += 4; if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length); if key == 5 { return base64.StdEncoding.EncodeToString(value) } }; return "" }
func runProxyServer(addr string) { listener, err := net.Listen("tcp", addr); if err != nil { log.Fatalf("[代理] 监听失败: %v", err) }; defer listener.Close(); log.Printf("[代理] 服务器启动: %s (支持 SOCKS5 和 HTTP)", addr); for { conn, err := listener.Accept(); if err != nil { continue }; go handleConnection(conn) } }
func handleConnection(conn net.Conn) { defer conn.Close(); clientAddr := conn.RemoteAddr().String(); conn.SetDeadline(time.Now().Add(30 * time.Second)); buf := make([]byte, 1); n, err := conn.Read(buf); if err != nil || n == 0 { return }; conn.SetDeadline(time.Time{}); firstByte := buf[0]; switch firstByte { case 0x05: handleSOCKS5(conn, clientAddr, firstByte); case 'C', 'G', 'P', 'H', 'D', 'O', 'T': handleHTTP(conn, clientAddr, firstByte); default: log.Printf("[代理] %s 未知协议: 0x%02x", clientAddr, firstByte) } }
func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame []byte) error { wsConn, err := dialWebSocketWithECH(2); if err != nil { sendErrorResponse(conn, mode); return err }; defer wsConn.Close(); var mu sync.Mutex; stopPing := make(chan bool); go func() { ticker := time.NewTicker(10 * time.Second); defer ticker.Stop(); for { select { case <-ticker.C: mu.Lock(); wsConn.WriteMessage(websocket.PingMessage, nil); mu.Unlock(); case <-stopPing: return } } }(); defer close(stopPing); conn.SetDeadline(time.Time{}); if firstFrame == nil && mode == 1 { _ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); buffer := make([]byte, 32*1024); n, _ := conn.Read(buffer); _ = conn.SetReadDeadline(time.Time{}); if n > 0 { firstFrame = buffer[:n] } }; encodedFrame := ""; if len(firstFrame) > 0 { encodedFrame = base64.StdEncoding.EncodeToString(firstFrame) }; connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, encodedFrame); mu.Lock(); err = wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); mu.Unlock(); if err != nil { sendErrorResponse(conn, mode); return err }; _, msg, err := wsConn.ReadMessage(); if err != nil { sendErrorResponse(conn, mode); return err }; response := string(msg); if strings.HasPrefix(response, "ERROR:") { sendErrorResponse(conn, mode); return errors.New(response) }; if response != "CONNECTED" { sendErrorResponse(conn, mode); return fmt.Errorf("意外响应: %s", response) }; if err := sendSuccessResponse(conn, mode); err != nil { return err }; log.Printf("[代理] %s 已连接: %s", clientAddr, target); done := make(chan bool, 2); go func() { buf := make([]byte, 32768); for { n, err := conn.Read(buf); if err != nil { mu.Lock(); wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE")); mu.Unlock(); done <- true; return }; mu.Lock(); err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); mu.Unlock(); if err != nil { done <- true; return } } }(); go func() { for { mt, msg, err := wsConn.ReadMessage(); if err != nil { done <- true; return }; if mt == websocket.TextMessage { if string(msg) == "CLOSE" { done <- true; return } }; if _, err := conn.Write(msg); err != nil { done <- true; return } } }(); <-done; log.Printf("[代理] %s 已断开: %s", clientAddr, target); return nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; slashIdx := strings.Index(addr, "/"); if slashIdx != -1 { path = addr[slashIdx:]; addr = addr[:slashIdx] }; host, port, err = net.SplitHostPort(addr); if err != nil { return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err) }; return host, port, path, nil }
func sendErrorResponse(conn net.Conn, mode int) { switch mode { case 1: conn.Write([]byte{0x05, 0x04, 0, 1, 0, 0, 0, 0, 0, 0}); case 2, 3: conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) } }
func sendSuccessResponse(conn net.Conn, mode int) error { switch mode { case 1: _, err := conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0}); return err; case 2: _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); return err; case 3: return nil }; return nil }
