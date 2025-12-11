// ech-workers.exe 内核代码 (最终智能分流版)
// 集成了 Xray-core 路由引擎，可根据 geoip.dat 和 geosite.dat 实现智能分流。
// 访问国内目标 (geoip:cn, geosite:cn) 时将进行直连，其他目标则通过 ECH 隧道代理。
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

	"github.com/gorilla/websocket"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/geodata/standard"
	"google.golang.org/protobuf/proto"
)

// ======================== 全局变量与初始化 ========================

var (
	listenAddr     string
	serverAddr     string
	serverIP       string
	token          string
	dnsPrimary     string
	dnsFallback    string
	echDomain      string
	echListMu      sync.RWMutex
	echList        []byte
	routerInstance routing.Router // 用于路由决策的核心实例
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

// ======================== 主函数 ========================

func main() {
	flag.Parse()
	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 -f")
	}

	// 步骤1: 初始化路由引擎
	if err := initRouter(); err != nil {
		log.Printf("[路由] 警告: 路由引擎初始化失败: %v", err)
		log.Printf("[路由] 所有流量将默认通过代理。请确保 geoip.dat 和 geosite.dat 在程序同目录下。")
	}

	// 步骤2: 准备 ECH 配置
	log.Printf("[启动] 正在获取 ECH 配置 (双轨模式)...")
	if err := prepareECH(); err != nil {
		log.Fatalf("[启动] 所有 ECH 配置获取方式均失败: %v", err)
	}

	// 步骤3: 启动代理服务器
	runProxyServer(listenAddr)
}

// ======================== 路由分流核心 (新增部分) ========================

func initRouter() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取可执行文件路径: %w", err)
	}
	dataDir := filepath.Dir(execPath)
	geoipPath := filepath.Join(dataDir, "geoip.dat")
	geositePath := filepath.Join(dataDir, "geosite.dat")

	// 检查文件是否存在，不存在则无法进行分流
	if _, err := os.Stat(geoipPath); os.IsNotExist(err) {
		return fmt.Errorf("geoip.dat 未找到于: %s", geoipPath)
	}
	if _, err := os.Stat(geositePath); os.IsNotExist(err) {
		return fmt.Errorf("geosite.dat 未找到于: %s", geositePath)
	}

	config := &router.Config{
		DomainStrategy: router.DomainStrategy_IpIfNonMatch,
		Rule: []*router.RoutingRule{
			{
				Geoip:     []*router.GeoIP{{CountryCode: "cn", Path: geoipPath}},
				TargetTag: "direct",
			},
			{
				Geosite:   []*router.Geosite{{CountryCode: "cn", Path: geositePath}},
				TargetTag: "direct",
			},
		},
	}

	router.DefaultGeoIPLoader = standard.NewLoader(geoipPath)
	router.DefaultGeositeLoader = standard.NewLoader(geositePath)

	r, err := router.New(context.Background(), config)
	if err != nil {
		return fmt.Errorf("创建路由引擎失败: %w", err)
	}
	routerInstance = r
	log.Println("[路由] 引擎初始化成功，已加载 CN 分流规则")
	return nil
}

func shouldProxy(target string) bool {
	if routerInstance == nil {
		return true // 如果路由引擎未初始化，默认所有流量都走代理
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target // 如果没有端口，整个 target 就是 host
	}

	var route routing.Route
	ip := net.ParseIP(host)
	if ip != nil {
		route, err = routerInstance.PickRoute(context.Background(), routing.Target{
			Network: xraynet.Network_TCP, Address: xraynet.IPAddress(ip),
		})
	} else {
		route, err = routerInstance.PickRoute(context.Background(), routing.Target{
			Network: xraynet.Network_TCP, Address: xraynet.DomainAddress(host),
		})
	}

	if err == nil && route.GetTag() == "direct" {
		return false // 匹配到 "direct" 标签，执行直连
	}

	return true // 其他情况（未匹配、决策失败）都走代理
}

func pipeConnections(clientConn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()
	wg.Wait()
}

// ======================== ECH & DoH 核心 (原始部分) ========================

func prepareECH() error {
	var echBase64 string
	var err error
	if dnsPrimary != "" {
		log.Printf("[启动] 正在通过首选 DOH 代理 [%s] 获取...", dnsPrimary)
		echBase64, err = queryHTTPSRecord(echDomain, dnsPrimary)
		if err == nil && echBase64 != "" {
			log.Printf("[启动] 通过 DOH 代理 Worker 成功获取！")
			goto DecodeECH
		}
		log.Printf("[警告] 通过首选 DOH 代理失败: %v。正在尝试备用方案...", err)
	}
	if dnsFallback != "" {
		log.Printf("[启动] 正在通过备用公共 DOH [%s] 获取...", dnsFallback)
		echBase64, err = queryHTTPSRecord(echDomain, dnsFallback)
		if err != nil {
			return fmt.Errorf("备用公共 DOH 方案也失败了: %w", err)
		}
		if echBase64 == "" {
			return errors.New("通过备用公共 DOH 未找到 ECH 参数")
		}
		log.Printf("[启动] 通过备用公共 DOH 成功获取！")
	} else {
		return errors.New("没有配置任何有效的 ECH 配置获取方式 (dns 或 dns-fallback)")
	}

DecodeECH:
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 配置解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

const typeHTTPS = 65

func isNormalCloseError(err error) bool { if err == nil { return false }; if err == io.EOF { return true }; errStr := err.Error(); return strings.Contains(errStr, "use of closed network connection") || strings.Contains(errStr, "broken pipe") || strings.Contains(errStr, "connection reset by peer") || strings.Contains(errStr, "normal closure") }
func getECHList() ([]byte, error) { echListMu.RLock(); defer echListMu.RUnlock(); if len(echList) == 0 { return nil, errors.New("ECH 配置未加载") }; return echList, nil }
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) { roots, err := x509.SystemCertPool(); if err != nil { return nil, fmt.Errorf("加载系统根证书失败: %w", err) }; return &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: serverName, EncryptedClientHelloConfigList: echList, EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error { return errors.New("服务器拒绝 ECH") }, RootCAs: roots, }, nil }
func queryHTTPSRecord(domain, dnsServer string) (string, error) { dohURL := dnsServer; if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") { dohURL = "https://" + dohURL }; return queryDoH(domain, dohURL) }
func queryDoH(domain, dohURL string) (string, error) { u, err := url.Parse(dohURL); if err != nil { return "", fmt.Errorf("无效的 DoH URL: %v", err) }; dnsQuery := buildDNSQuery(domain, typeHTTPS); dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery); q := u.Query(); q.Set("dns", dnsBase64); u.RawQuery = q.Encode(); req, err := http.NewRequest("GET", u.String(), nil); if err != nil { return "", fmt.Errorf("创建请求失败: %v", err) }; req.Header.Set("Accept", "application/dns-message"); req.Header.Set("Content-Type", "application/dns-message"); client := &http.Client{Timeout: 10 * time.Second}; resp, err := client.Do(req); if err != nil { return "", fmt.Errorf("DoH 请求失败: %w", err) }; defer resp.Body.Close(); if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode) }; body, err := io.ReadAll(resp.Body); if err != nil { return "", fmt.Errorf("读取 DoH 响应失败: %v", err) }; return parseDNSResponse(body) }
func buildDNSQuery(domain string, qtype uint16) []byte { query := make([]byte, 0, 512); query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00); for _, label := range strings.Split(domain, ".") { query = append(query, byte(len(label))); query = append(query, []byte(label)...) }; query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01); return query }
func parseDNSResponse(response []byte) (string, error) { if len(response) < 12 { return "", errors.New("响应过短") }; ancount := binary.BigEndian.Uint16(response[6:8]); if ancount == 0 { return "", errors.New("无应答记录") }; offset := 12; for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset += 5; for i := 0; i < int(ancount); i++ { if offset >= len(response) { break }; if response[offset]&0xC0 == 0xC0 { offset += 2 } else { for offset < len(response) && response[offset] != 0 { offset += int(response[offset]) + 1 }; offset++ }; if offset+10 > len(response) { break }; rrType := binary.BigEndian.Uint16(response[offset : offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(response[offset : offset+2]); offset += 2; if offset+int(dataLen) > len(response) { break }; data := response[offset : offset+int(dataLen)]; offset += int(dataLen); if rrType == typeHTTPS { if ech := parseHTTPSRecord(data); ech != "" { return ech, nil } } }; return "", errors.New("在DNS响应中未找到HTTPS记录") }
func parseHTTPSRecord(data []byte) string { if len(data) < 2 { return "" }; offset := 2; if offset < len(data) && data[offset] == 0 { offset++ } else { for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++ }; for offset+4 <= len(data) { key := binary.BigEndian.Uint16(data[offset : offset+2]); length := binary.BigEndian.Uint16(data[offset+2 : offset+4]); offset += 4; if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length); if key == 5 { return base64.StdEncoding.EncodeToString(value) } }; return "" }

// ======================== 代理服务器逻辑 (修改后) ========================

func runProxyServer(addr string) { listener, err := net.Listen("tcp", addr); if err != nil { log.Fatalf("[代理] 监听失败: %v", err) }; defer listener.Close(); log.Printf("[代理] 服务器启动: %s (支持智能分流)", addr); for { conn, err := listener.Accept(); if err != nil { continue }; go handleConnection(conn) } }
func handleConnection(conn net.Conn) { defer conn.Close(); conn.SetReadDeadline(time.Now().Add(5 * time.Second)); buf := make([]byte, 1); n, err := conn.Read(buf); if err != nil || n == 0 { return }; conn.SetReadDeadline(time.Time{}); switch buf[0] { case 0x05: handleSOCKS5(conn, buf[0]); default: handleHTTP(conn, buf[0]) } }

func handleSOCKS5(conn net.Conn, firstByte byte) {
	buf := make([]byte, 1); if _, err := io.ReadFull(conn, buf); err != nil { return }; nmethods := buf[0]; methods := make([]byte, nmethods); if _, err := io.ReadFull(conn, methods); err != nil { return }; conn.Write([]byte{0x05, 0x00}); buf = make([]byte, 4); if _, err := io.ReadFull(conn, buf); err != nil { return }; atyp := buf[3]; var host string; switch atyp { case 0x01: ipBuf := make([]byte, 4); if _, err := io.ReadFull(conn, ipBuf); err != nil { return }; host = net.IP(ipBuf).String(); case 0x03: lenBuf := make([]byte, 1); if _, err := io.ReadFull(conn, lenBuf); err != nil { return }; domBuf := make([]byte, lenBuf[0]); if _, err := io.ReadFull(conn, domBuf); err != nil { return }; host = string(domBuf) }; portBuf := make([]byte, 2); if _, err := io.ReadFull(conn, portBuf); err != nil { return }; port := binary.BigEndian.Uint16(portBuf); target := fmt.Sprintf("%s:%d", host, port);

	if !shouldProxy(target) {
		log.Printf("[分流] SOCKS5 直连 -> %s", target)
		targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil { conn.Write([]byte{0x05, 0x04, 0, 1, 0, 0, 0, 0, 0, 0}); return }
		conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		pipeConnections(conn, targetConn)
		return
	}

	log.Printf("[分流] SOCKS5 代理 -> %s", target)
	handleTunnel(conn, target, conn.RemoteAddr().String(), 1, nil)
}

func handleHTTP(conn net.Conn, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn)); requestLine, err := reader.ReadString('\n'); if err != nil { return }; parts := strings.Fields(requestLine); if len(parts) < 3 { return }; method, requestURL := parts[0], parts[1];

	if method == "CONNECT" {
		target := requestURL
		if !strings.Contains(target, ":") { target += ":443" }

		if !shouldProxy(target) {
			log.Printf("[分流] CONNECT 直连 -> %s", target)
			targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil { conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); return }
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			pipeConnections(conn, targetConn)
			return
		}
		
		log.Printf("[分流] CONNECT 代理 -> %s", target)
		handleTunnel(conn, target, conn.RemoteAddr().String(), 2, nil)
	} else {
		// 暂不支持非CONNECT方法的直连，统一代理
		host := ""
		if h, _, err := net.SplitHostPort(parts[1]); err == nil {
			host = h
		} else if u, err := url.Parse(parts[1]); err == nil {
			host = u.Host
		} else if h, ok := reader.Peek(1024); ok == nil { // Simplified Host header peek
			lines := strings.Split(string(h), "\r\n")
			for _, line := range lines {
				if strings.HasPrefix(strings.ToLower(line), "host:") {
					host = strings.TrimSpace(line[5:])
					break
				}
			}
		}

		log.Printf("[分流] HTTP %s 代理 -> %s", method, host)
		if !strings.Contains(host, ":") { host += ":80" }

		// Re-assemble the initial request data
		initialData := []byte(requestLine)
		for {
			line, err := reader.ReadString('\n')
			initialData = append(initialData, []byte(line)...)
			if line == "\r\n" || err != nil { break }
		}
		handleTunnel(conn, host, conn.RemoteAddr().String(), 3, initialData)
	}
}


// ======================== WebSocket ECH 隧道 (原始部分) ========================

func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame []byte) error {
	wsConn, err := dialWebSocketWithECH(2)
	if err != nil { sendErrorResponse(conn, mode); return err }
	defer wsConn.Close();

	encodedFrame := ""; if len(firstFrame) > 0 { encodedFrame = base64.StdEncoding.EncodeToString(firstFrame) }
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, encodedFrame)
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil { return err }

	_, msg, err := wsConn.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" { sendErrorResponse(conn, mode); return errors.New("proxy connect failed") }
	
	if err := sendSuccessResponse(conn, mode); err != nil { return err }

	done := make(chan bool, 2)
	go func() { buf := make([]byte, 32768); for { n, err := conn.Read(buf); if err != nil { wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE")); break }; wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]) }; done <- true }()
	go func() { for { _, msg, err := wsConn.ReadMessage(); if err != nil { break }; conn.Write(msg) }; done <- true }()
	<-done
	return nil
}

func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(serverAddr)
	if err != nil { return nil, err }
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil { if attempt < maxRetries { if prepareECH() == nil { continue } }; return nil, echErr }
		
		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil { return nil, tlsErr }
		
		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols:    func() []string { if token == "" { return nil }; return []string{token} }(),
			HandshakeTimeout: 10 * time.Second,
		}
		
		if serverIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address); if err != nil { return nil, err }
				return net.DialTimeout(network, net.JoinHostPort(serverIP, port), 10*time.Second)
			}
		}
		
		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				log.Printf("[ECH] 连接失败，尝试刷新配置 (%d/%d)", attempt, maxRetries)
				if prepareECH() == nil { continue }
				time.Sleep(time.Second)
			}
			return nil, dialErr
		}
		return wsConn, nil
	}
	return nil, errors.New("连接失败，已达最大重试次数")
}

func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; slashIdx := strings.Index(addr, "/"); if slashIdx != -1 { path = addr[slashIdx:]; addr = addr[:slashIdx] }; host, port, err = net.SplitHostPort(addr); if err != nil { return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err) }; return host, port, path, nil }
func sendErrorResponse(conn net.Conn, mode int) { switch mode { case 1: conn.Write([]byte{0x05, 0x04, 0, 1, 0, 0, 0, 0, 0, 0}); case 2, 3: conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) } }
func sendSuccessResponse(conn net.Conn, mode int) error { switch mode { case 1: _, err := conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0}); return err; case 2: _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); return err; case 3: return nil }; return nil }
