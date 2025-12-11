// ech-workers.exe 内核代码 (最终智能分流版 - 兼容 xray-core v1.8.11)
package main

import (
	"bufio"
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
	"strings"
	"sync"
	"time"

	"github.comcom/gorilla/websocket"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/geodata/standard" // 关键：使用旧版 xray-core 的正确 import 路径
	"google.golang.org/protobuf/proto"
)

var (
	listenAddr     string; serverAddr     string; serverIP       string; token          string
	dnsPrimary     string; dnsFallback    string; echDomain      string; echListMu      sync.RWMutex
	echList        []byte; routerInstance routing.Router
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

func main() {
	flag.Parse(); if serverAddr == "" { log.Fatal("必须指定服务端地址 -f") }
	if err := initRouter(); err != nil { log.Printf("[路由] 警告: %v", err); log.Printf("[路由] 所有流量将默认代理。") }
	if err := prepareECH(); err != nil { log.Fatalf("[启动] ECH 配置获取失败: %v", err) }
	runProxyServer(listenAddr)
}

func initRouter() error {
	execPath, err := os.Executable(); if err != nil { return err }
	dataDir := filepath.Dir(execPath)
	geoipPath := filepath.Join(dataDir, "geoip.dat")
	geositePath := filepath.Join(dataDir, "geosite.dat")
	if _, err := os.Stat(geoipPath); os.IsNotExist(err) { return fmt.Errorf("geoip.dat 未找到") }
	if _, err := os.Stat(geositePath); os.IsNotExist(err) { return fmt.Errorf("geosite.dat 未找到") }

	config := &router.Config{
		DomainStrategy: router.DomainStrategy_IpIfNonMatch,
		Rule: []*router.RoutingRule{
			{Geoip: []*router.GeoIP{{CountryCode: "cn"}}, TargetTag: "direct"},
			{Geosite: []*router.Geosite{{CountryCode: "cn"}}, TargetTag: "direct"},
		},
	}
	router.DefaultGeoIPLoader, err = standard.NewLoader(geoipPath)
	if err != nil { return fmt.Errorf("加载 geoip.dat 失败: %w", err) }
	router.DefaultGeositeLoader, err = standard.NewLoader(geositePath)
	if err != nil { return fmt.Errorf("加载 geosite.dat 失败: %w", err) }
	
	r, err := router.New(context.Background(), config); if err != nil { return err }
	routerInstance = r
	log.Println("[路由] 引擎初始化成功，已加载 CN 分流规则")
	return nil
}

func shouldProxy(target string) bool {
	if routerInstance == nil { return true }
	host, _, _ := net.SplitHostPort(target); if host == "" { host = target }
	var route routing.Route; var err error
	ip := net.ParseIP(host)
	if ip != nil {
		route, err = routerInstance.PickRoute(context.Background(), routing.Target{Network: xraynet.Network_TCP, Address: xraynet.IPAddress(ip)})
	} else {
		route, err = routerInstance.PickRoute(context.Background(), routing.Target{Network: xraynet.Network_TCP, Address: xraynet.DomainAddress(host)})
	}
	return !(err == nil && route.GetTag() == "direct")
}

func pipeConnections(c1, c2 net.Conn) { go io.Copy(c1, c2); io.Copy(c2, c1); c1.Close(); c2.Close() }

func prepareECH() error {
	var echBase64 string; var err error
	if dnsPrimary != "" { echBase64, err = queryHTTPSRecord(echDomain, dnsPrimary); if err == nil && echBase64 != "" { goto DecodeECH } }
	echBase64, err = queryHTTPSRecord(echDomain, dnsFallback); if err != nil { return err }
DecodeECH:
	raw, err := base64.StdEncoding.DecodeString(echBase64); if err != nil { return err }
	echListMu.Lock(); echList = raw; echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw)); return nil
}

const typeHTTPS = 65
func getECHList() ([]byte, error) { echListMu.RLock(); defer echListMu.RUnlock(); if len(echList) == 0 { return nil, errors.New("ECH 配置未加载") }; return echList, nil }
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) { roots, _ := x509.SystemCertPool(); return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, EncryptedClientHelloConfigList: echList, EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error { return errors.New("ECH Rejected") }, RootCAs: roots,}, nil }
func queryHTTPSRecord(domain, dnsServer string) (string, error) { dohURL := dnsServer; if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") { dohURL = "https://" + dohURL }; return queryDoH(domain, dohURL) }
func queryDoH(domain, dohURL string) (string, error) { u, err := url.Parse(dohURL); if err != nil { return "", err }; dnsQuery := buildDNSQuery(domain, typeHTTPS); dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery); q := u.Query(); q.Set("dns", dnsBase64); u.RawQuery = q.Encode(); req, _ := http.NewRequest("GET", u.String(), nil); req.Header.Set("Accept", "application/dns-message"); client := &http.Client{Timeout: 10 * time.Second}; resp, err := client.Do(req); if err != nil { return "", err }; defer resp.Body.Close(); body, _ := io.ReadAll(resp.Body); return parseDNSResponse(body) }
func buildDNSQuery(domain string, qtype uint16) []byte { query := make([]byte, 0, 512); query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00); for _, label := range strings.Split(domain, ".") { query = append(query, byte(len(label))); query = append(query, []byte(label)...) }; query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01); return query }
func parseDNSResponse(response []byte) (string, error) { if len(response) < 12 { return "", errors.New("short") }; ancount := binary.BigEndian.Uint16(response[6:8]); offset := 12; for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset += 5; for i := 0; i < int(ancount); i++ { if offset >= len(response) { break }; if response[offset]&0xC0 == 0xC0 { offset += 2 } else { for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset++ }; if offset+10 > len(response) { break }; rrType := binary.BigEndian.Uint16(response[offset : offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(response[offset : offset+2]); offset += 2; data := response[offset : offset+int(dataLen)]; offset += int(dataLen); if rrType == typeHTTPS { if ech := parseHTTPSRecord(data); ech != "" { return ech, nil } } }; return "", errors.New("not found") }
func parseHTTPSRecord(data []byte) string { if len(data) < 2 { return "" }; offset := 2; if offset < len(data) && data[offset] == 0 { offset++ } else { for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++ }; for offset+4 <= len(data) { key := binary.BigEndian.Uint16(data[offset : offset+2]); length := binary.BigEndian.Uint16(data[offset+2 : offset+4]); offset += 4; if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length); if key == 5 { return base64.StdEncoding.EncodeToString(value) } }; return "" }
func runProxyServer(addr string) { listener, err := net.Listen("tcp", addr); if err != nil { log.Fatalf("[代理] 监听失败: %v", err) }; log.Printf("[代理] 服务器启动: %s", addr); for { conn, err := listener.Accept(); if err == nil { go handleConnection(conn) } } }
func handleConnection(conn net.Conn) { defer conn.Close(); buf := make([]byte, 1); if n, err := conn.Read(buf); err != nil || n == 0 { return }; if buf[0] == 0x05 { handleSOCKS5(conn) } else { handleHTTP(conn, buf[0]) } }
func handleSOCKS5(conn net.Conn) { conn.Write([]byte{0x05, 0x00}); buf := make([]byte, 4); if _, err := io.ReadFull(conn, buf[1:]); err != nil { return }; var host string; switch buf[3] { case 0x01: ip := make([]byte, 4); io.ReadFull(conn, ip); host = net.IP(ip).String(); case 0x03: l := make([]byte, 1); io.ReadFull(conn, l); d := make([]byte, l[0]); io.ReadFull(conn, d); host = string(d) }; p := make([]byte, 2); io.ReadFull(conn, p); port := binary.BigEndian.Uint16(p); target := fmt.Sprintf("%s:%d", host, port); if !shouldProxy(target) { log.Printf("[分流] 直连 -> %s", target); tConn, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { conn.Write([]byte{0x05, 0x04}); return }; conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0}); pipeConnections(conn, tConn); return }; log.Printf("[分流] 代理 -> %s", target); handleTunnel(conn, target, 1, nil) }
func handleHTTP(conn net.Conn, firstByte byte) { r := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn)); l, _ := r.ReadString('\n'); p := strings.Fields(l); if len(p) < 2 { return }; if p[0] == "CONNECT" { target := p[1]; if !shouldProxy(target) { log.Printf("[分流] 直连 -> %s", target); tConn, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { conn.Write([]byte("HTTP/1.1 502\r\n\r\n")); return }; conn.Write([]byte("HTTP/1.1 200\r\n\r\n")); pipeConnections(conn, tConn); return }; log.Printf("[分流] 代理 -> %s", target); handleTunnel(conn, target, 2, nil) } }
func handleTunnel(conn net.Conn, target string, mode int, firstFrame []byte) { wsConn, err := dialWebSocketWithECH(2); if err != nil { return }; defer wsConn.Close(); f := ""; if len(firstFrame) > 0 { f = base64.StdEncoding.EncodeToString(firstFrame) }; msg := fmt.Sprintf("CONNECT:%s|%s", target, f); wsConn.WriteMessage(websocket.TextMessage, []byte(msg)); _, resp, err := wsConn.ReadMessage(); if err != nil || string(resp) != "CONNECTED" { return }; if mode == 1 { conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0}) } else { conn.Write([]byte("HTTP/1.1 200\r\n\r\n")) }; go func() { io.Copy(conn, wsConn.UnderlyingConn()) }(); io.Copy(wsConn.UnderlyingConn(), conn) }
func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) { host, port, path, _ := parseServerAddr(serverAddr); wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path); for i := 0; i < maxRetries; i++ { echBytes, err := getECHList(); if err != nil { return nil, err }; tlsCfg, _ := buildTLSConfigWithECH(host, echBytes); dialer := websocket.Dialer{TLSClientConfig: tlsCfg, Subprotocols: []string{token}, HandshakeTimeout: 10 * time.Second}; if serverIP != "" { dialer.NetDial = func(n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(serverIP, p), 10*time.Second) } }; wsConn, _, err := dialer.Dial(wsURL, nil); if err == nil { return wsConn, nil }; if strings.Contains(err.Error(), "ECH") { prepareECH(); time.Sleep(1 * time.Second) } else { return nil, err } }; return nil, errors.New("retries exceeded") }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; s := strings.Index(addr, "/"); if s != -1 { path = addr[s:]; addr = addr[:s] }; host, port, err = net.SplitHostPort(addr); return }
