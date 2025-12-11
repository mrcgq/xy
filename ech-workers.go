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
	routingMode string // 分流模式

	// DNS 配置 (来自 V2 的双轨设计)
	dnsWorker string // 首选：Worker 代理 DoH
	dnsPublic string // 备用：公共 DoH

	echListMu sync.RWMutex
	echList   []byte

	// 中国IP列表（IPv4 & IPv6 - 来自 V1）
	chinaIPRangesMu   sync.RWMutex
	chinaIPRanges     []ipRange
	chinaIPV6RangesMu sync.RWMutex
	chinaIPV6Ranges   []ipRangeV6
)

// ipRange 表示一个IPv4 IP范围
type ipRange struct {
	start uint32
	end   uint32
}

// ipRangeV6 表示一个IPv6 IP范围
type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}

func init() {
	// 基础参数
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址 (支持 SOCKS5 和 HTTP)")
	flag.StringVar(&serverAddr, "f", "", "服务端地址 (格式: x.x.workers.dev:443)")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP（绕过 DNS 解析）")
	flag.StringVar(&token, "token", "", "身份验证令牌")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")

	// 增强的 DNS 参数 (V2 特性)
	flag.StringVar(&dnsWorker, "dns", "", "首选 ECH 获取源: DOH 代理 Worker 地址 (推荐)")
	flag.StringVar(&dnsPublic, "dns-fallback", "https://dns.alidns.com/dns-query", "备用 ECH 获取源: 公共 DOH 服务器")

	// 分流参数 (V1 特性)
	flag.StringVar(&routingMode, "routing", "global", "分流模式: global(全局), bypass_cn(绕过大陆), none(直连)")
}

func main() {
	flag.Parse()

	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 -f\n示例: ./client -l 127.0.0.1:1080 -f your.worker.dev:443 -token xxx")
	}

	// 1. 获取 ECH 配置 (使用 V2 的双轨机制)
	log.Printf("[启动] 正在初始化 ECH 配置 (双轨模式)...")
	if err := prepareECH(); err != nil {
		log.Fatalf("[致命] 获取 ECH 配置失败: %v", err)
	}

	// 2. 加载分流规则 (使用 V1 的智能分流)
	if routingMode == "bypass_cn" {
		log.Printf("[启动] 分流模式: 绕过中国大陆，正在加载 IP 列表...")
		loadChinaLists()
	} else {
		log.Printf("[启动] 分流模式: %s", routingMode)
	}

	runProxyServer(listenAddr)
}

// ======================== ECH 核心逻辑 (V2 增强版) ========================

const typeHTTPS = 65

// prepareECH 实现双轨获取：优先尝试 Worker 代理，失败则回退到公共 DNS
func prepareECH() error {
	var echBase64 string
	var err error

	// 轨道 1: 尝试通过 Worker 代理获取 (抗干扰能力强)
	if dnsWorker != "" {
		log.Printf("[ECH] 尝试通过首选源 [%s] 获取...", dnsWorker)
		echBase64, err = queryHTTPSRecord(echDomain, dnsWorker)
		if err == nil && echBase64 != "" {
			log.Printf("[ECH] 通过首选源获取成功！")
			goto Decode
		}
		log.Printf("[ECH] 首选源失败: %v，切换至备用源...", err)
	}

	// 轨道 2: 尝试通过公共 DNS 获取 (兼容性好)
	if dnsPublic != "" {
		log.Printf("[ECH] 尝试通过备用源 [%s] 获取...", dnsPublic)
		echBase64, err = queryHTTPSRecord(echDomain, dnsPublic)
		if err != nil {
			return fmt.Errorf("备用源查询失败: %w", err)
		}
		if echBase64 == "" {
			return errors.New("备用源未返回有效 ECH 记录")
		}
		log.Printf("[ECH] 通过备用源获取成功！")
	} else {
		return errors.New("未配置有效的 ECH 获取源")
	}

Decode:
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置为空")
	}
	return echList, nil
}

func refreshECH() {
	log.Printf("[ECH] 正在刷新配置...")
	if err := prepareECH(); err != nil {
		log.Printf("[警告] ECH 刷新失败: %v", err)
	}
}

// queryHTTPSRecord 通用查询函数
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

// queryDoH 执行 DoH 查询
func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效 URL: %v", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

// parseDNSResponse 解析 DNS 响应
func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	// 跳过 Question Section
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5 // 0x00 + QTYPE + QCLASS

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		// 跳过 Name
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8 // Type(2) + Class(2) + TTL(4)
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", errors.New("未找到 HTTPS 记录")
}

// parseHTTPSRecord 解析 HTTPS 记录 (使用 V2 的修复版逻辑)
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2 // Priority
	// 跳过 TargetName
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}

	// 解析 SvcParams
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)

		// 核心修复: 兼容 Key=5 (Draft/Old standard)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== TLS 配置与反射 ========================

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}

	if err := setECHConfig(config, echList); err != nil {
		return nil, fmt.Errorf("设置 ECH 失败 (需 Go 1.23+): %w", err)
	}

	return config, nil
}

func setECHConfig(config *tls.Config, echList []byte) error {
	configValue := reflect.ValueOf(config).Elem()
	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if !field1.IsValid() || !field1.CanSet() {
		return fmt.Errorf("不支持 EncryptedClientHelloConfigList")
	}
	field1.Set(reflect.ValueOf(echList))

	field2 := configValue.FieldByName("EncryptedClientHelloRejectionVerify")
	if field2.IsValid() && field2.CanSet() {
		rejectionFunc := func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		}
		field2.Set(reflect.ValueOf(rejectionFunc))
	}
	return nil
}

// ======================== IP 列表管理 (V1 特性) ========================

func loadChinaLists() {
	ipv4Count := 0
	ipv6Count := 0

	if err := loadIPList("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); err != nil {
		log.Printf("[警告] 加载 IPv4 列表失败: %v", err)
	} else {
		chinaIPRangesMu.RLock()
		ipv4Count = len(chinaIPRanges)
		chinaIPRangesMu.RUnlock()
	}

	if err := loadIPList("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true); err != nil {
		log.Printf("[警告] 加载 IPv6 列表失败 (非致命): %v", err)
	} else {
		chinaIPV6RangesMu.RLock()
		ipv6Count = len(chinaIPV6Ranges)
		chinaIPV6RangesMu.RUnlock()
	}

	if ipv4Count > 0 || ipv6Count > 0 {
		log.Printf("[IP库] 已加载 %d 个 IPv4 段, %d 个 IPv6 段", ipv4Count, ipv6Count)
	} else {
		log.Printf("[警告] 未加载任何 IP 列表，分流模式可能失效")
	}
}

// loadIPList 通用加载函数，支持自动下载
func loadIPList(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) error {
	exePath, _ := os.Executable()
	filePath := filepath.Join(filepath.Dir(exePath), filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		filePath = filename // 尝试当前目录
	}

	// 自动下载
	if info, err := os.Stat(filePath); os.IsNotExist(err) || info.Size() == 0 {
		url := "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/" + filename
		log.Printf("[下载] 正在下载 IP 列表: %s", filename)
		if err := downloadFile(url, filePath); err != nil {
			return err
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var rangesV4 []ipRange
	var rangesV6 []ipRangeV6

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}

		if isV6 {
			var s, e [16]byte
			copy(s[:], startIP.To16())
			copy(e[:], endIP.To16())
			rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e})
		} else {
			s := ipToUint32(startIP)
			e := ipToUint32(endIP)
			if s > 0 && e > 0 {
				rangesV4 = append(rangesV4, ipRange{start: s, end: e})
			}
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if isV6 {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6))
	} else {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4))
	}
	return nil
}

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// shouldBypassProxy 判断是否直连
func shouldBypassProxy(targetHost string) bool {
	if routingMode == "none" {
		return true
	}
	if routingMode == "global" {
		return false
	}
	if routingMode == "bypass_cn" {
		if ip := net.ParseIP(targetHost); ip != nil {
			return isChinaIP(ip)
		}
		// 域名解析后判断
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if isChinaIP(ip) {
				return true
			}
		}
	}
	return false
}

func isChinaIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		val := ipToUint32(ip4)
		chinaIPRangesMu.RLock()
		defer chinaIPRangesMu.RUnlock()
		for _, r := range chinaIPRanges {
			if val >= r.start && val <= r.end {
				return true
			}
		}
		return false
	}
	// IPv6 check
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	var val [16]byte
	copy(val[:], ip16)
	chinaIPV6RangesMu.RLock()
	defer chinaIPV6RangesMu.RUnlock()
	for _, r := range chinaIPV6Ranges {
		if compareIPv6(val, r.start) >= 0 && compareIPv6(val, r.end) <= 0 {
			return true
		}
	}
	return false
}

func compareIPv6(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ======================== WebSocket 连接 ========================

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	return
}

func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				refreshECH()
				continue
			}
			return nil, echErr
		}

		tlsCfg, _ := buildTLSConfigWithECH(host, echBytes)
		dialer := websocket.Dialer{
			TLSClientConfig:  tlsCfg,
			HandshakeTimeout: 10 * time.Second,
			Subprotocols: func() []string {
				if token != "" {
					return []string{token}
				}
				return nil
			}(),
		}

		if serverIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(address)
				return net.DialTimeout(network, net.JoinHostPort(serverIP, p), 10*time.Second)
			}
		}

		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			if strings.Contains(err.Error(), "ECH") && attempt < maxRetries {
				log.Printf("[重连] ECH 可能失效，正在刷新... (%d/%d)", attempt, maxRetries)
				refreshECH()
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.New("连接失败")
}

// ======================== 代理服务逻辑 ========================

func runProxyServer(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	log.Printf("[服务] 监听地址: %s", addr)
	log.Printf("[服务] 后端服务器: %s", serverAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] == 0x05 {
		handleSOCKS5(conn)
	} else {
		handleHTTP(conn, buf[0])
	}
}

// ---------------- SOCKS5 ----------------

func handleSOCKS5(conn net.Conn) {
	// Handshake
	buf := make([]byte, 256)
	n, err := io.ReadAtLeast(conn, buf, 1) // NMETHODS
	if err != nil {
		return
	}
	nMethods := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // NO AUTH

	// Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	cmd := buf[1]
	atyp := buf[3]
	var host string

	switch atyp {
	case 1: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		host = string(buf[:domainLen])
	case 4: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)

	if cmd == 0x01 { // CONNECT
		log.Printf("[SOCKS5] TCP 连接: %s", target)
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		startTunnel(conn, target, false, nil)
	} else if cmd == 0x03 { // UDP ASSOCIATE (V1 特性)
		handleUDPAssociate(conn)
	} else {
		conn.Write([]byte{0x05, 0x07, 0, 0, 0, 0, 0, 0}) // Cmd not supported
	}
}

// ---------------- UDP / DNS 处理 (V1 特性) ----------------

func handleUDPAssociate(tcpConn net.Conn) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}
	lAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := lAddr.Port

	// Reply success
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	resp = append(resp, portBytes...)
	tcpConn.Write(resp)

	log.Printf("[SOCKS5] UDP 关联开启: %d", port)
	go func() {
		buf := make([]byte, 1)
		tcpConn.Read(buf) // Keep TCP alive
		udpConn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		go processUDP(udpConn, addr, buf[:n])
	}
}

func processUDP(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	if len(data) < 3 {
		return
	}
	// FRAG(1) + ATYP(1) ...
	if data[2] != 0x00 { // No fragment support
		return
	}
	// Parse header to find dest port
	pos := 3
	atyp := data[pos]
	pos++
	switch atyp {
	case 1:
		pos += 4
	case 3:
		pos += int(data[pos]) + 1
	case 4:
		pos += 16
	}
	if len(data) < pos+2 {
		return
	}
	port := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	payload := data[pos:]

	if port == 53 {
		// DoH Query Logic (通过 ECH 隧道查 DNS)
		// 构建 DoH 请求到 Cloudflare
		go func() {
			resp, err := queryDoHForProxy(payload)
			if err == nil {
				// Construct UDP header back
				resHeader := make([]byte, pos)
				copy(resHeader, data[:pos])
				final := append(resHeader, resp...)
				conn.WriteToUDP(final, clientAddr)
			}
		}()
	}
}

// queryDoHForProxy 使用 ECH 配置通过 HTTPS 查询 Cloudflare DNS
func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	echBytes, err := getECHList()
	if err != nil {
		return nil, err
	}
	tlsCfg, _ := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	if serverIP != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(serverIP, p), 10*time.Second)
		}
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(dnsQuery))
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ---------------- HTTP ----------------

func handleHTTP(conn net.Conn, firstByte byte) {
	// Reconstruct buffer
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return
	}
	method := parts[0]
	urlStr := parts[1]

	var target string
	if method == "CONNECT" {
		target = urlStr
		log.Printf("[HTTP] CONNECT: %s", target)
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		startTunnel(conn, target, false, nil)
	} else {
		// Proxy Request
		if strings.HasPrefix(urlStr, "http://") {
			u, _ := url.Parse(urlStr)
			target = u.Host
			if !strings.Contains(target, ":") {
				target += ":80"
			}
			path := u.Path
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
			newReqLine := fmt.Sprintf("%s %s %s\r\n", method, path, parts[2])
			
			// Read remaining headers
			var headers bytes.Buffer
			headers.WriteString(newReqLine)
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					headers.WriteString("\r\n")
					break
				}
				if !strings.HasPrefix(strings.ToLower(line), "proxy-") {
					headers.WriteString(line)
				}
			}
			// Read Body if exists (simplification)
			rest, _ := io.ReadAll(reader) // Note: this blocks if Keep-Alive, simplified for example
			allData := append(headers.Bytes(), rest...)
			log.Printf("[HTTP] Proxy: %s", target)
			startTunnel(conn, target, true, allData)
		}
	}
}

// ---------------- 隧道逻辑 ----------------

func startTunnel(clientConn net.Conn, target string, isDirectHTTP bool, firstFrame []byte) {
	// 1. 分流判断
	host, _, _ := net.SplitHostPort(target)
	if shouldBypassProxy(host) {
		log.Printf("[分流] 直连: %s", target)
		startDirect(clientConn, target, firstFrame)
		return
	}

	// 2. 走代理
	clientConn.SetDeadline(time.Time{})
	wsConn, err := dialWebSocketWithECH(2)
	if err != nil {
		log.Printf("[隧道] 连接 WebSocket 失败: %v", err)
		return
	}
	defer wsConn.Close()

	// 构造握手包
	encoded := ""
	if len(firstFrame) > 0 {
		encoded = base64.StdEncoding.EncodeToString(firstFrame)
	}
	cmd := fmt.Sprintf("CONNECT:%s|%s", target, encoded)
	wsConn.WriteMessage(websocket.TextMessage, []byte(cmd))

	// 等待响应
	_, msg, err := wsConn.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" {
		log.Printf("[隧道] 握手失败: %s", string(msg))
		return
	}

	// 管道转发
	errChan := make(chan error, 2)
	
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				errChan <- err
				return
			}
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		for {
			mt, data, err := wsConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if mt == websocket.TextMessage && string(data) == "CLOSE" {
				errChan <- io.EOF
				return
			}
			if _, err := clientConn.Write(data); err != nil {
				errChan <- err
				return
			}
		}
	}()

	<-errChan
}

func startDirect(clientConn net.Conn, target string, firstFrame []byte) {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	if len(firstFrame) > 0 {
		remote.Write(firstFrame)
	}

	go io.Copy(remote, clientConn)
	io.Copy(clientConn, remote)
}
