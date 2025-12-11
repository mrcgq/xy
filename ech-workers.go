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

	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr  string
	serverAddr  string
	serverIP    string
	token       string
	echDomain   string
	routingMode string

	dnsWorker string
	dnsPublic string

	echListMu sync.RWMutex
	echList   []byte

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

// ======================== ECH and IP List Management (No Changes) ========================
const typeHTTPS = 65
func prepareECH() error { var echBase64 string; var err error; if dnsWorker != "" { echBase64, err = queryHTTPSRecord(echDomain, dnsWorker); if err == nil && echBase64 != "" { goto Decode }; log.Printf("[ECH] 首选源失败: %v...", err) }; if dnsPublic != "" { echBase64, err = queryHTTPSRecord(echDomain, dnsPublic); if err != nil { return err }; if echBase64 == "" { return errors.New("备用源未返回 ECH") } } else { return errors.New("未配置 ECH 获取源") }; Decode: raw, err := base64.StdEncoding.DecodeString(echBase64); if err != nil { return err }; echListMu.Lock(); echList = raw; echListMu.Unlock(); log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw)); return nil }
func getECHList() ([]byte, error) { echListMu.RLock(); defer echListMu.RUnlock(); if len(echList) == 0 { return nil, errors.New("ECH 配置为空") }; return echList, nil }
func refreshECH() { if err := prepareECH(); err != nil { log.Printf("[警告] ECH 刷新失败: %v", err) } }
func queryHTTPSRecord(domain, dnsServer string) (string, error) { if !strings.HasPrefix(dnsServer, "https://") && !strings.HasPrefix(dnsServer, "http://") { dnsServer = "https://" + dnsServer }; return queryDoH(domain, dnsServer) }
func queryDoH(domain, dohURL string) (string, error) { u, err := url.Parse(dohURL); if err != nil { return "", err }; dnsQuery := buildDNSQuery(domain, typeHTTPS); q := u.Query(); q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsQuery)); u.RawQuery = q.Encode(); req, err := http.NewRequest("GET", u.String(), nil); if err != nil { return "", err }; req.Header.Set("Accept", "application/dns-message"); client := &http.Client{Timeout: 10 * time.Second}; resp, err := client.Do(req); if err != nil { return "", err }; defer resp.Body.Close(); if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("HTTP %d", resp.StatusCode) }; body, err := io.ReadAll(resp.Body); if err != nil { return "", err }; return parseDNSResponse(body) }
func buildDNSQuery(domain string, qtype uint16) []byte { var q []byte; q = append(q, []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0} ...); for _, label := range strings.Split(domain, ".") { q = append(q, byte(len(label))); q = append(q, label...) }; q = append(q, 0); q = binary.BigEndian.AppendUint16(q, qtype); q = binary.BigEndian.AppendUint16(q, 1); return q }
func parseDNSResponse(r []byte) (string, error) { if len(r) < 12 || binary.BigEndian.Uint16(r[6:8]) == 0 { return "", errors.New("无应答记录") }; offset := 12; for r[offset] != 0 { offset += int(r[offset]) + 1 }; offset += 5; for { if offset+10 > len(r) { break }; offset += 2; if r[offset-2]&0xC0 == 0xC0 { } else { for r[offset-1] != 0 { offset += int(r[offset-1]) + 1 } }; rrType := binary.BigEndian.Uint16(r[offset : offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(r[offset : offset+2]); offset += 2; if offset+int(dataLen) > len(r) { break }; data := r[offset : offset+int(dataLen)]; offset += int(dataLen); if rrType == typeHTTPS { if ech := parseHTTPSRecord(data); ech != "" { return ech, nil } } }; return "", errors.New("未找到HTTPS记录") }
func parseHTTPSRecord(data []byte) string { if len(data) < 2 { return "" }; offset := 2; for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++; for offset+4 <= len(data) { key := binary.BigEndian.Uint16(data[offset:offset+2]); length := binary.BigEndian.Uint16(data[offset+2:offset+4]); offset += 4; if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length); if key == 5 { return base64.StdEncoding.EncodeToString(value) } }; return "" }
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) { roots, err := x509.SystemCertPool(); if err != nil { return nil, err }; config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots}; v := reflect.ValueOf(config).Elem(); f := v.FieldByName("EncryptedClientHelloConfigList"); if !f.IsValid() || !f.CanSet() { return nil, errors.New("不支持 ECH") }; f.Set(reflect.ValueOf(echList)); return config, nil }
func loadChinaLists() { if err := loadIPList("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); err == nil { chinaIPRangesMu.RLock(); log.Printf("[IP库] 已加载 %d 个 IPv4 段", len(chinaIPRanges)); chinaIPRangesMu.RUnlock() } else { log.Printf("[警告] 加载 IPv4 列表失败: %v", err) }; if err := loadIPList("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true); err == nil { chinaIPV6RangesMu.RLock(); log.Printf("[IP库] 已加载 %d 个 IPv6 段", len(chinaIPV6Ranges)); chinaIPV6RangesMu.RUnlock() } else { log.Printf("[警告] 加载 IPv6 列表失败: %v", err) } }
func loadIPList(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) error { exePath, _ := os.Executable(); filePath := filepath.Join(filepath.Dir(exePath), filename); if _, err := os.Stat(filePath); os.IsNotExist(err) { filePath = filename }; if info, err := os.Stat(filePath); os.IsNotExist(err) || info.Size() == 0 { url := "https://mirror.ghproxy.com/https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/" + filename; log.Printf("[下载] 正在下载 IP 列表: %s", filename); if err := downloadFile(url, filePath); err != nil { return err } }; file, err := os.Open(filePath); if err != nil { return err }; defer file.Close(); var rangesV4 []ipRange; var rangesV6 []ipRangeV6; scanner := bufio.NewScanner(file); for scanner.Scan() { parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }; startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }; if isV6 { var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16()); rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e}) } else { s, e := ipToUint32(startIP), ipToUint32(endIP); if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) } } }; mu.Lock(); defer mu.Unlock(); if isV6 { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6)) } else { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) }; return nil }
func downloadFile(url, path string) error { resp, err := http.Get(url); if err != nil { return err }; defer resp.Body.Close(); if resp.StatusCode != 200 { return fmt.Errorf("HTTP %d", resp.StatusCode) }; data, err := io.ReadAll(resp.Body); if err != nil { return err }; return os.WriteFile(path, data, 0644) }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func shouldBypassProxy(targetHost string) bool { if routingMode == "none" { return true }; if routingMode == "global" { return false }; if routingMode == "bypass_cn" { if ip := net.ParseIP(targetHost); ip != nil { return isChinaIP(ip) }; ips, err := net.LookupIP(targetHost); if err != nil { return false }; for _, ip := range ips { if isChinaIP(ip) { return true } } }; return false }
func isChinaIP(ip net.IP) bool { if ip4 := ip.To4(); ip4 != nil { val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock(); for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } } } else if ip16 := ip.To16(); ip16 != nil { var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock(); for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } } }; return false }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return }
func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) { host, port, path, err := parseServerAddr(serverAddr); if err != nil { return nil, err }; wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path); for attempt := 1; attempt <= maxRetries; attempt++ { echBytes, err := getECHList(); if err != nil { if attempt < maxRetries { refreshECH(); continue }; return nil, err }; tlsCfg, _ := buildTLSConfigWithECH(host, echBytes); dialer := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{token}}; if serverIP != "" { dialer.NetDial = func(n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(serverIP, p), 10*time.Second) } }; conn, _, err := dialer.Dial(wsURL, nil); if err != nil { if strings.Contains(err.Error(), "ECH") && attempt < maxRetries { log.Printf("[重连] ECH 可能失效，正在刷新..."); refreshECH(); time.Sleep(1 * time.Second); continue }; return nil, err }; return conn, nil }; return nil, errors.New("连接失败") }

// ======================== Proxy Logic (Fully Restored & Fixed) ========================

const (
	modeSOCKS5      = 1
	modeHTTPConnect = 2
	modeHTTPProxy   = 3
)

func runProxyServer(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil { log.Fatalf("监听失败: %v", err) }
	log.Printf("[服务] 监听地址: %s", addr); log.Printf("[服务] 后端服务器: %s", serverAddr)
	for { conn, err := l.Accept(); if err == nil { go handleConnection(conn) } }
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	buf := make([]byte, 1); if _, err := conn.Read(buf); err != nil { return }
	switch buf[0] {
	case 0x05: handleSOCKS5(conn, clientAddr)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T': handleHTTP(conn, clientAddr, buf[0])
	default: log.Printf("[代理] %s 未知协议: 0x%02x", clientAddr, buf[0])
	}
}

func handleSOCKS5(conn net.Conn, clientAddr string) {
	if _, err := conn.Read(make([]byte, 1)); err != nil { return }
	if _, err := conn.Read(make([]byte, 1)); err != nil { return }
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return }
	header := make([]byte, 4); if _, err := io.ReadFull(conn, header); err != nil { return }
	cmd, atyp := header[1], header[3]; var host string
	switch atyp {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	default: return
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	switch cmd {
	case 0x01: // CONNECT
		log.Printf("[SOCKS5] %s -> %s", clientAddr, target)
		if err := handleTunnel(conn, target, nil, modeSOCKS5); err != nil {
			log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
		}
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(conn, clientAddr)
	default: conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	req, err := http.ReadRequest(reader); if err != nil { return }
	if req.Method == "CONNECT" {
		log.Printf("[HTTP] %s -> CONNECT %s", clientAddr, req.Host)
		if err := handleTunnel(conn, req.Host, nil, modeHTTPConnect); err != nil {
			log.Printf("[HTTP] %s 代理失败: %v", clientAddr, err)
		}
	} else {
		log.Printf("[HTTP] %s -> %s %s", clientAddr, req.Method, req.URL.Host)
		var buf bytes.Buffer; req.WriteProxy(&buf)
		if err := handleTunnel(conn, req.URL.Host, buf.Bytes(), modeHTTPProxy); err != nil {
			log.Printf("[HTTP] %s 代理失败: %v", clientAddr, err)
		}
	}
}

// 【【【最终修复的关键函数】】】
func handleTunnel(clientConn net.Conn, target string, firstFrame []byte, mode int) error {
	host, _, _ := net.SplitHostPort(target); if host == "" { host = target }
	if shouldBypassProxy(host) {
		log.Printf("[分流] %s 直连", target)
		return startDirect(clientConn, target, firstFrame, mode)
	}
	wsConn, err := dialWebSocketWithECH(2); if err != nil { sendErrorResponse(clientConn, mode); return err }
	defer wsConn.Close()
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil { sendErrorResponse(clientConn, mode); return err }
	_, msg, err := wsConn.ReadMessage(); if err != nil || string(msg) != "CONNECTED" { sendErrorResponse(clientConn, mode); return fmt.Errorf("握手失败: %s", string(msg)) }
	if err := sendSuccessResponse(clientConn, mode); err != nil { return err }
	log.Printf("[代理] %s 已连接", target)

	// 使用正确的手动循环，而不是 io.Copy
	done := make(chan bool, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				done <- true; return
			}
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				done <- true; return
			}
		}
	}()
	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil {
				clientConn.Close()
				done <- true; return
			}
			if _, err := clientConn.Write(msg); err != nil {
				done <- true; return
			}
		}
	}()
	<-done
	log.Printf("[代理] %s 已断开", target)
	return nil
}

func startDirect(clientConn net.Conn, target string, firstFrame []byte, mode int) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { sendErrorResponse(clientConn, mode); return err }
	defer remote.Close()
	if err := sendSuccessResponse(clientConn, mode); err != nil { return err }
	if len(firstFrame) > 0 { remote.Write(firstFrame) }
	done := make(chan bool, 2)
	go func() { io.Copy(remote, clientConn); done <- true }()
	go func() { io.Copy(clientConn, remote); done <- true }()
	<-done
	return nil
}

func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case modeSOCKS5, modeHTTPConnect: conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
	case modeHTTPProxy: conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, mode int) error {
	var err error
	switch mode {
	case modeSOCKS5: _, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	case modeHTTPConnect: _, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	case modeHTTPProxy: return nil
	}
	return err
}

// UDP feature restored
func handleUDPAssociate(tcpConn net.Conn, clientAddr string) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0"); udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil { log.Printf("[UDP] %s 监听失败: %v", clientAddr, err); return }
	lAddr := udpConn.LocalAddr().(*net.UDPAddr); port := lAddr.Port; log.Printf("[UDP] %s 关联开启于端口: %d", clientAddr, port)
	resp := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}; tcpConn.Write(resp)
	go func() { tcpConn.Read(make([]byte, 1)); udpConn.Close() }()
	buf := make([]byte, 2048)
	for {
		n, addr, err := udpConn.ReadFromUDP(buf); if err != nil { break }
		go processUDP(udpConn, addr, buf[:n], clientAddr)
	}
}
func processUDP(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, tcpClientAddr string) {
	if len(data) < 6 || data[2] != 0 { return }; pos := 3; atyp := data[pos]; pos++; var host string
	switch atyp {
	case 1: host = net.IP(data[pos : pos+4]).String(); pos += 4
	case 3: host = string(data[pos+1 : pos+1+int(data[pos])]); pos += 1 + int(data[pos])
	case 4: host = net.IP(data[pos : pos+16]).String(); pos += 16
	}
	port := binary.BigEndian.Uint16(data[pos : pos+2]); pos += 2; payload := data[pos:]
	if port == 53 {
		log.Printf("[UDP-DNS] %s -> %s:%d (DoH查询)", tcpClientAddr, host, port)
		go func() {
			resp, err := queryDoHForProxy(payload); if err == nil {
				resHdr := make([]byte, pos); copy(resHdr, data[:pos]); final := append(resHdr, resp...); conn.WriteToUDP(final, clientAddr)
			}
		}()
	}
}
func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	echBytes, err := getECHList(); if err != nil { return nil, err }; tlsCfg, _ := buildTLSConfigWithECH("cloudflare-dns.com", echBytes); tr := &http.Transport{TLSClientConfig: tlsCfg}
	if serverIP != "" { tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(serverIP, p), 10*time.Second) } }
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}; req, _ := http.NewRequest("POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(dnsQuery)); req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req); if err != nil { return nil, err }; defer resp.Body.Close(); return io.ReadAll(resp.Body)
}
