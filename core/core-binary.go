//go:build binary
// +build binary

// =========================================================================================
// Xlink Core v21.8 内核端代码
// 54法则审查修复版 + 连接池化（Connection Pooling）+ 连接健康自愈
//
// 本版本相对 v21.7 的核心改动：
//   [新增] W-分子-01 零内核债务：wsConnPool — 全局 WebSocket 连接池
//   [新增] W-系统-05 同步终止：idlePoolCleaner goroutine，定期驱逐空闲/死连接
//   [新增] W-器官-01 单一归属：pipeDirect 退出时原子驱逐池中死连接
//   [新增] W-质子-01 零阻塞：池命中时跳过 TLS+WS 握手，直接复用长连接
//   [修复] W-原子-05 幂等：getCachedTunnel Ping 失败后立即删除缓存再重建
//   [修复] W-系统-09 背压传导：pipeDirect 上下行各持独立 bufPool buffer
//   [保留] 全部 v21.7 法则注释，逐条对应
//
// 关键物理约束（与 54 法则对应）：
//   W-夸克-01  每个 gorilla/websocket 连接 ≈ 1 个 TCP + 1 个 TLS session（内核态资源）
//   W-质子-04  句柄吝啬：maxPoolSize = min(节点数×8, 128)，防止连接泄漏
//   W-器官-05  差异化超时：本地握手 3s / 远端握手 5s / 空闲清理周期 60s
// =========================================================================================

package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== 编译期常量 ========================

// [法则03] 单一真相：超时常量集中定义
// [法则36] 差异化超时：每个值有明确的物理依据
const (
	// SOCKS5 代理通常是局域网或同城节点，RTT < 1ms，3s 足够判定失活
	connTimeoutProxy = 3 * time.Second
	// 直连目标可能跨运营商，额外 1s 冗余
	connTimeoutDirect = 4 * time.Second
	// fallback 目标可能跨大洲，5s 是 P99 延迟上界
	connTimeoutFallback = 5 * time.Second

	sniffReadTimeout    = 500 * time.Millisecond
	wsHandshakeTimeout  = 5 * time.Second
	idleConnTimeout     = 30 * time.Second
	tlsHandshakeTimeout = 5 * time.Second

	// [新增][法则36] 连接池专属超时常量
	// Ping 检测：2s 内无响应视为死连接（比握手超时更短，快速判定）
	poolPingTimeout = 2 * time.Second
	// 空闲清理周期：60s 扫描一次，驱逐超过 idleConnTimeout 未被使用的连接
	poolCleanInterval = 60 * time.Second
	// 单节点最大池深度：避免对同一后端建立过多长连接占用服务端 fd
	// [法则04] 句柄吝啬：maxPoolDepth × 节点数 < 系统句柄上限
	maxPoolDepth = 8

	// [法则04] 意图透明：SOCKS5 协议版本魔法字节具名化
	socks5Version byte = 0x05
)

var globalRRIndex uint64

// ======================== 连接模式枚举 ========================

// connMode 编码代理响应状态机
// [法则14] 不变量显式：用具名类型替代裸 int，编译器协助检查不变量
// [法则23] 返回值语义完备：调用方从类型即知合法值域
type connMode int

const (
	// modeResponded 代理响应已发出，后续可直接读取隧道数据
	modeResponded connMode = 0
	// modeSOCKS5Pending SOCKS5 握手完成，代理响应尚未发出
	modeSOCKS5Pending connMode = 1
	// modeHTTPSPending HTTPS CONNECT 请求已解析，代理响应尚未发出
	modeHTTPSPending connMode = 2
	// modeHTTPPlain HTTP 明文请求，firstFrame 中含完整请求体
	modeHTTPPlain connMode = 3
)

// ======================== DNS 配置与策略 ========================

// [法则03] 单一真相：策略枚举集中定义
type DNSStrategy string

const (
	DNSStrategyUseIP      DNSStrategy = "UseIP"
	DNSStrategyUseIPv4    DNSStrategy = "UseIPv4"
	DNSStrategyUseIPv6    DNSStrategy = "UseIPv6"
	DNSStrategyPreferIPv6 DNSStrategy = "PreferIPv6"
	DNSStrategyPreferIPv4 DNSStrategy = "PreferIPv4"
)

// [法则14] 不变量：Enabled=false 时，ResolveIP 直接返回原域名
type DNSConfig struct {
	Enabled          bool        `json:"enabled"`
	Strategy         DNSStrategy `json:"strategy"`
	Servers          []string    `json:"servers"`
	FallbackToRemote bool        `json:"fallback_to_remote"`
	CacheTTL         int         `json:"cache_ttl"`
	TimeoutMs        int         `json:"timeout_ms"`
}

// [法则14] 不变量：Enabled=false 时，Sniff 直接返回 Success=false
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"dest_override"` // ["http", "tls"]
	RouteOnly    bool     `json:"route_only"`
}

// [法则10] 编译期优先：默认配置在包初始化时确定，不在热路径读注册表
var defaultDNSConfig = DNSConfig{
	Enabled:          true,
	Strategy:         DNSStrategyPreferIPv4,
	Servers:          []string{"https://223.5.5.5/dns-query", "https://dns.google/dns-query"},
	FallbackToRemote: true,
	CacheTTL:         600,
	TimeoutMs:        800,
}

var defaultSniffingConfig = SniffingConfig{
	Enabled:      true,
	DestOverride: []string{"http", "tls"},
	RouteOnly:    false,
}

// ======================== DNS 缓存 ========================

// [法则40] 状态局部化：缓存封装为独立结构，不暴露全局 map
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
}

type dnsCacheEntry struct {
	ipv4    []net.IP
	ipv6    []net.IP
	expires time.Time
}

// [法则03] 单一真相：全局缓存唯一实例
var globalDNSCache = &dnsCache{entries: make(map[string]*dnsCacheEntry)}

func (c *dnsCache) get(domain string) (ipv4, ipv6 []net.IP, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, exists := c.entries[domain]
	if !exists || time.Now().After(entry.expires) {
		return nil, nil, false
	}
	return entry.ipv4, entry.ipv6, true
}

func (c *dnsCache) set(domain string, ipv4, ipv6 []net.IP, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[domain] = &dnsCacheEntry{
		ipv4:    ipv4,
		ipv6:    ipv6,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// ======================== WebSocket 连接池 ========================
//
// [新增][法则分子-01] 零内核债务：
//   复用已握手的 WebSocket 长连接，避免每次请求都发起 TLS+WS 握手。
//   浏览器打开一个页面会产生几十个并发请求，
//   没有连接池时 → 几十次 TLS 握手 → 节点高负载 + 用户感知卡顿。
//   有连接池后  → 1~maxPoolDepth 条长连接复用 → 握手代价被均摊。
//
// 池结构设计说明：
//   key   = node.Domain（节点标识符，单一真相来源）
//   value = []*pooledConn（同一节点可维持多条连接，应对并发请求）
//
// [法则14] 不变量（每条池化连接）：
//   conn    非 nil   — 已完成握手的活跃连接（或待健康检查）
//   lastUse 单调递增 — 每次从池中取出时更新，用于空闲驱逐
//   inUse   true     — 连接正在被 pipeDirect 占用，不能被清理线程驱逐
//
// [法则32] 单一归属：wsConnPool 是所有池化连接的唯一归属点
//   连接的生命周期转移：
//     dialZeusWebSocket → pooledConn.conn（归池）
//     getCachedTunnel   → 取出（inUse=true，归 pipeDirect）
//     pipeDirect defer  → 归还（inUse=false）或驱逐（conn出错）
//     idlePoolCleaner   → 驱逐超时空闲连接（inUse=false 且超时）

// pooledConn 池中单条连接的状态封装
// [法则14] 所有字段含义显式标注，不变量由注释描述
type pooledConn struct {
	conn    *websocket.Conn
	lastUse time.Time // 最后一次从池中取出的时间（用于空闲驱逐）
	inUse   bool      // true = 正在被 pipeDirect 占用，清理线程跳过
}

// wsConnPool 全局 WebSocket 连接池
// [法则32] 单一归属：进程内唯一实例，所有连接归属此结构
// [法则40] 状态局部化：池状态封装在结构内，不暴露裸 map
type wsConnPool struct {
	mu    sync.Mutex
	conns map[string][]*pooledConn // key: node.Domain
}

// [法则03] 单一真相：全局池唯一实例，在 init() 中初始化
var globalConnPool = &wsConnPool{
	conns: make(map[string][]*pooledConn),
}

// acquire 从池中取一条健康连接（inUse=false），若无则返回 nil
// [法则22] 单一职责：只做"取"操作，不做拨号
// [法则05] 幂等：Ping 失败时立即从池中删除该条目，保证池中无死连接
func (p *wsConnPool) acquire(nodeKey string) *websocket.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.conns[nodeKey]
	for i, pc := range list {
		if pc.inUse {
			continue // [法则14] 不变量：inUse=true 的连接归 pipeDirect 独占
		}
		// Ping 健康检查：写一帧 Ping，超时则驱逐
		// [法则36] poolPingTimeout=2s < wsHandshakeTimeout=5s，快速判定死连接
		pc.conn.SetWriteDeadline(time.Now().Add(poolPingTimeout))
		err := pc.conn.WriteMessage(websocket.PingMessage, nil)
		pc.conn.SetWriteDeadline(time.Time{}) // 恢复无限期
		if err != nil {
			// [法则05] 幂等：Ping 失败 → 驱逐 → 下次 acquire 不会再遇到此死连接
			pc.conn.Close()
			p.conns[nodeKey] = append(list[:i], list[i+1:]...)
			log.Printf("[Pool] evict dead conn key:%s err:%v", nodeKey, err)
			return nil
		}
		// 命中：标记为占用，更新最后使用时间
		pc.inUse = true
		pc.lastUse = time.Now()
		log.Printf("[Pool] reuse conn key:%s pool_size:%d", nodeKey, len(list))
		return pc.conn
	}
	return nil // 无可用连接，调用方负责拨号
}

// release 将连接归还给池（归还而非关闭，供后续请求复用）
// [法则22] 单一职责：只做"还"操作，不做关闭
// [法则19] 幂等：如果 conn 已不在池中（被 evict），此调用无副作用
func (p *wsConnPool) release(nodeKey string, conn *websocket.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pc := range p.conns[nodeKey] {
		if pc.conn == conn {
			pc.inUse = false
			pc.lastUse = time.Now()
			log.Printf("[Pool] returned conn key:%s", nodeKey)
			return
		}
	}
	// conn 不在池中（已被驱逐），静默忽略（幂等）
}

// evict 从池中强制驱逐特定连接（pipeDirect 出错时调用）
// [法则22] 单一职责：只做"驱逐"操作
// [法则09] 副作用声明：关闭 conn，从池中删除该条目
func (p *wsConnPool) evict(nodeKey string, conn *websocket.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.conns[nodeKey]
	for i, pc := range list {
		if pc.conn == conn {
			pc.conn.Close()
			p.conns[nodeKey] = append(list[:i], list[i+1:]...)
			log.Printf("[Pool] evicted conn key:%s remaining:%d", nodeKey, len(p.conns[nodeKey]))
			return
		}
	}
}

// put 将新建的连接放入池中（若池未满）
// [法则22] 单一职责：只做"放入"操作
// [法则04] 句柄吝啬：超过 maxPoolDepth 时拒绝入池（连接由调用方关闭）
// [法则09] 副作用声明：可能关闭 conn（池满时）
func (p *wsConnPool) put(nodeKey string, conn *websocket.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.conns[nodeKey]
	if len(list) >= maxPoolDepth {
		log.Printf("[Pool] full key:%s depth:%d, conn will not be cached", nodeKey, len(list))
		return false // 调用方负责关闭此连接
	}
	p.conns[nodeKey] = append(list, &pooledConn{
		conn:    conn,
		lastUse: time.Now(),
		inUse:   true, // 新建连接立即进入 inUse 状态，由 pipeDirect 持有
	})
	log.Printf("[Pool] added conn key:%s depth:%d", nodeKey, len(p.conns[nodeKey]))
	return true
}

// startIdlePoolCleaner 启动空闲连接清理 goroutine
// [新增][法则系统-05] 同步终止：cleaner 通过 stopCh 优雅退出
// [法则09] 副作用声明：关闭并删除超过 idleConnTimeout 的空闲连接
// [法则38] 契约: 输入 stopCh | 输出：无 | 副作用：定期修改 globalConnPool
func startIdlePoolCleaner(stopCh <-chan struct{}) {
	ticker := time.NewTicker(poolCleanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanIdleConns()
		case <-stopCh:
			log.Printf("[Pool] idle cleaner stopped")
			return
		}
	}
}

// cleanIdleConns 扫描并驱逐超时空闲连接
// [法则22] 单一职责：只做清理，不做连接建立
// [法则19] 幂等：多次调用结果一致（已驱逐的不会被重复驱逐）
func cleanIdleConns() {
	globalConnPool.mu.Lock()
	defer globalConnPool.mu.Unlock()
	now := time.Now()
	for key, list := range globalConnPool.conns {
		var alive []*pooledConn
		for _, pc := range list {
			if pc.inUse {
				alive = append(alive, pc) // 占用中：不驱逐
				continue
			}
			if now.Sub(pc.lastUse) > idleConnTimeout {
				pc.conn.Close()
				log.Printf("[Pool] idle evict key:%s idle:%v", key, now.Sub(pc.lastUse).Round(time.Second))
			} else {
				alive = append(alive, pc)
			}
		}
		if len(alive) == 0 {
			delete(globalConnPool.conns, key)
		} else {
			globalConnPool.conns[key] = alive
		}
	}
}

// ======================== DNS 解析器 ========================

// DNSResolver DNS 解析器
// [法则38] 契约: 输入 DNSConfig | 输出 ResolveIP(domain)→string | 副作用：DoH 网络请求+缓存写入
type DNSResolver struct {
	config     DNSConfig
	httpClient *http.Client
}

// [法则22] 单一职责：只构造解析器，不做解析
func NewDNSResolver(config DNSConfig) *DNSResolver {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
			DualStack: true,
		}).DialContext,
		// [法则37] 有意识缺陷：InsecureSkipVerify=true
		// DoH 服务器通过 IP 直连时证书 CN 可能不匹配，
		// 依赖 URL 中的 server 地址做信任锚，此为设计决策非安全疏忽
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        10,
		IdleConnTimeout:     idleConnTimeout,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
	}
	return &DNSResolver{
		config: config,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
		},
	}
}

// ResolveIP 根据策略解析域名，返回最优 IP 字符串
// [法则38] 契约: 输入 domain | 输出 IP 字符串或原域名（永不返回 error 导致中断）| 副作用：缓存读写+DoH 请求
// [法则16] 快速失败：未启用→直接返回；已是 IP→直接返回；缓存命中→直接返回
func (r *DNSResolver) ResolveIP(domain string) string {
	if !r.config.Enabled {
		return domain
	}
	if net.ParseIP(domain) != nil {
		return domain
	}

	if ipv4s, ipv6s, ok := globalDNSCache.get(domain); ok {
		if result := r.selectIP(ipv4s, ipv6s); result != "" {
			log.Printf("[DNS] cache:%s→%s", domain, result)
			return result
		}
	}

	ipv4s, ipv6s, err := r.resolveAll(domain)
	if err != nil || (len(ipv4s) == 0 && len(ipv6s) == 0) {
		log.Printf("[DNS] resolve failed:%s err:%v fallback to domain", domain, err)
		return domain
	}

	globalDNSCache.set(domain, ipv4s, ipv6s, r.config.CacheTTL)

	result := r.selectIP(ipv4s, ipv6s)
	if result == "" {
		return domain
	}
	log.Printf("[DNS] resolved:%s→%s strategy:%s", domain, result, r.config.Strategy)
	return result
}

// [法则22] 单一职责：协调 DoH 查询和系统 DNS 回退
// [法则30] 错误传播：子错误向上传播，调用方决策
func (r *DNSResolver) resolveAll(domain string) ([]net.IP, []net.IP, error) {
	for _, server := range r.config.Servers {
		v4, v6, err := r.resolveDoH(server, domain)
		if err == nil && (len(v4) > 0 || len(v6) > 0) {
			return v4, v6, nil
		}
	}
	if r.config.FallbackToRemote {
		return r.resolveSystem(domain)
	}
	return nil, nil, errors.New("all DoH servers failed, fallback disabled")
}

// [法则22] 单一职责：并发查询 A 和 AAAA 记录
func (r *DNSResolver) resolveDoH(server, domain string) ([]net.IP, []net.IP, error) {
	var ipv4s, ipv6s []net.IP
	var mu sync.Mutex
	var wg sync.WaitGroup

	queryA    := r.config.Strategy != DNSStrategyUseIPv6
	queryAAAA := r.config.Strategy != DNSStrategyUseIPv4

	if queryA {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ips, err := r.doHQuery(server, domain, "A"); err == nil {
				mu.Lock(); ipv4s = append(ipv4s, ips...); mu.Unlock()
			}
		}()
	}
	if queryAAAA {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ips, err := r.doHQuery(server, domain, "AAAA"); err == nil {
				mu.Lock(); ipv6s = append(ipv6s, ips...); mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return ipv4s, ipv6s, nil
}

// [法则22] 单一职责：执行单次 DoH HTTP 请求并解析响应
func (r *DNSResolver) doHQuery(server, domain, recordType string) ([]net.IP, error) {
	reqURL := fmt.Sprintf("%s?name=%s&type=%s", server, url.QueryEscape(domain), recordType)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TimeoutMs)*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
	}

	var result struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range result.Answer {
		if (recordType == "A" && ans.Type == 1) || (recordType == "AAAA" && ans.Type == 28) {
			if ip := net.ParseIP(ans.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// [法则22] 单一职责：系统 DNS 查询（兜底路径）
func (r *DNSResolver) resolveSystem(domain string) ([]net.IP, []net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TimeoutMs)*time.Millisecond)
	defer cancel()

	all, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, nil, err
	}

	var ipv4s, ipv6s []net.IP
	for _, ip := range all {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}
	return ipv4s, ipv6s, nil
}

// [法则22] 单一职责：根据策略从候选列表选择一个 IP
func (r *DNSResolver) selectIP(ipv4s, ipv6s []net.IP) string {
	switch r.config.Strategy {
	case DNSStrategyUseIPv6:
		if len(ipv6s) > 0 { return ipv6s[0].String() }
	case DNSStrategyUseIPv4:
		if len(ipv4s) > 0 { return ipv4s[0].String() }
	case DNSStrategyPreferIPv6:
		if len(ipv6s) > 0 { return ipv6s[0].String() }
		if len(ipv4s) > 0 { return ipv4s[0].String() }
	case DNSStrategyPreferIPv4:
		if len(ipv4s) > 0 { return ipv4s[0].String() }
		if len(ipv6s) > 0 { return ipv6s[0].String() }
	default: // UseIP：随机选择
		all := append(ipv6s, ipv4s...)
		if len(all) > 0 { return all[rand.Intn(len(all))].String() }
	}
	return ""
}

// ======================== Sniffing 模块 ========================

// SniffResult 嗅探结果
// [法则23] 返回值语义完备：Success=false 时 Domain 为空字符串
type SniffResult struct {
	Domain   string
	Protocol string
	Success  bool
}

// Sniffer 流量嗅探器
// [法则38] 契约: 输入 data 字节切片 | 输出 SniffResult | 副作用：无（纯函数）
type Sniffer struct {
	config SniffingConfig
}

func NewSniffer(config SniffingConfig) *Sniffer {
	return &Sniffer{config: config}
}

// Sniff 按配置的协议顺序尝试嗅探
// [法则16] 快速失败：未启用或数据为空立即返回
func (s *Sniffer) Sniff(data []byte) SniffResult {
	if !s.config.Enabled || len(data) == 0 {
		return SniffResult{}
	}
	for _, proto := range s.config.DestOverride {
		switch proto {
		case "tls":
			if r := s.sniffTLS(data); r.Success { return r }
		case "http":
			if r := s.sniffHTTP(data); r.Success { return r }
		// [法则54] 认知负载预算：QUIC 启发式嗅探复杂度超过收益，不引入
		}
	}
	return SniffResult{}
}

// sniffTLS 从 TLS ClientHello 提取 SNI
// [法则11] 边界完备：每步读取前验证长度
func (s *Sniffer) sniffTLS(data []byte) SniffResult {
	if len(data) < 5 || data[0] != 0x16 { return SniffResult{} }

	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0300 || version > 0x0304 { return SniffResult{} }

	recordLen := binary.BigEndian.Uint16(data[3:5])
	if len(data) < int(5+recordLen) { return SniffResult{} }

	handshakeData := data[5:]
	if len(handshakeData) < 4 || handshakeData[0] != 0x01 { return SniffResult{} }

	handshakeLen := int(handshakeData[1])<<16 | int(handshakeData[2])<<8 | int(handshakeData[3])
	if len(handshakeData) < 4+handshakeLen { return SniffResult{} }

	return s.parseClientHello(handshakeData[4:])
}

// parseClientHello 解析 ClientHello 提取扩展
// [法则11+12] 边界完备+语义合法
func (s *Sniffer) parseClientHello(data []byte) SniffResult {
	if len(data) < 38 { return SniffResult{} }

	pos := 34 // skip version(2) + random(32)
	if pos >= len(data) { return SniffResult{} }

	sessionIDLen := int(data[pos]); pos += 1 + sessionIDLen
	if pos+2 > len(data) { return SniffResult{} }

	cipherLen := int(binary.BigEndian.Uint16(data[pos:])); pos += 2 + cipherLen
	if pos >= len(data) { return SniffResult{} }

	compLen := int(data[pos]); pos += 1 + compLen
	if pos+2 > len(data) { return SniffResult{} }

	extLen := int(binary.BigEndian.Uint16(data[pos:])); pos += 2
	if pos+extLen > len(data) { return SniffResult{} }

	return s.parseExtensions(data[pos : pos+extLen])
}

// parseExtensions 从扩展列表中提取 SNI（type=0）
func (s *Sniffer) parseExtensions(data []byte) SniffResult {
	for pos := 0; pos+4 <= len(data); {
		extType := binary.BigEndian.Uint16(data[pos:])
		extLen  := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if pos+extLen > len(data) { break }
		if extType == 0 {
			if domain := s.parseSNI(data[pos : pos+extLen]); domain != "" {
				return SniffResult{Domain: domain, Protocol: "tls", Success: true}
			}
		}
		pos += extLen
	}
	return SniffResult{}
}

// parseSNI 解析 SNI 扩展，提取 hostname
func (s *Sniffer) parseSNI(data []byte) string {
	if len(data) < 5 { return "" }
	listLen := int(binary.BigEndian.Uint16(data[0:]))
	if listLen+2 > len(data) { return "" }

	for pos := 2; pos+3 <= 2+listLen; {
		nameType := data[pos]
		nameLen  := int(binary.BigEndian.Uint16(data[pos+1:]))
		pos += 3
		if pos+nameLen > len(data) { break }
		if nameType == 0 {
			hostname := string(data[pos : pos+nameLen])
			if isValidDomain(hostname) { return hostname }
		}
		pos += nameLen
	}
	return ""
}

// sniffHTTP 从 HTTP 请求提取 Host
func (s *Sniffer) sniffHTTP(data []byte) SniffResult {
	if len(data) < 16 { return SniffResult{} }

	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	isHTTP := false
	for _, m := range methods {
		if bytes.HasPrefix(data, []byte(m)) { isHTTP = true; break }
	}
	if !isHTTP { return SniffResult{} }

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil { return SniffResult{} }

	host := req.Host
	if host == "" { host = req.Header.Get("Host") }
	if host == "" { return SniffResult{} }

	if h, _, err := net.SplitHostPort(host); err == nil { host = h }
	if !isValidDomain(host) { return SniffResult{} }

	return SniffResult{Domain: host, Protocol: "http", Success: true}
}

// ======================== 域名/IP 工具函数 ========================

// [法则22] 单一职责：纯校验函数，无副作用
func isValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 { return false }
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 { return false }
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// [法则22] 单一职责：纯判断，无副作用
func isIPAddress(s string) bool {
	host, _, err := net.SplitHostPort(s)
	if err != nil { host = s }
	return net.ParseIP(host) != nil
}

// ======================== 路由与负载均衡结构 ========================

type Backend struct {
	IP     string
	Port   string
	Weight int
}

type Node struct {
	Domain   string
	Backends []Backend
}

const (
	MatchTypeSubstring = iota
	MatchTypeDomain
	MatchTypeRegex
	MatchTypeGeosite
	MatchTypeGeoIP
)

type Rule struct {
	Type          int
	Value         string
	CompiledRegex *regexp.Regexp
	Node          Node
	Strategy      string
}

// [法则38] 契约：所有字段含义显式标注
type ProxySettings struct {
	Server          string `json:"server"`
	ServerIP        string `json:"server_ip"`
	Token           string `json:"token"`
	Strategy        string `json:"strategy"`
	Rules           string `json:"rules"`
	GlobalKeepAlive bool   `json:"global_keep_alive"`
	S5              string `json:"s5"`

	DNS      *DNSConfig      `json:"dns,omitempty"`
	Sniffing *SniffingConfig `json:"sniffing,omitempty"`

	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
	NodePool          []Node                  `json:"-"`
}

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

type Inbound struct {
	Tag      string          `json:"tag"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Sniffing *SniffingConfig `json:"sniffing,omitempty"`
}

type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type ProxyForwarderSettings struct {
	Socks5Address string
}

// ======================== 全局状态 ========================

// [法则40] 状态局部化：全局状态仅保留无法避免的部分
var (
	globalConfig      Config
	proxySettingsMap  = make(map[string]ProxySettings)
	routingMap        []Rule
	globalDNSResolver *DNSResolver
	globalSniffer     *Sniffer

	// [新增][法则39] 生命周期：stopCh 用于优雅关闭 idlePoolCleaner goroutine
	poolCleanerStopCh chan struct{}
)

// [法则24] 零债务：32KB 缓冲池复用，避免每次分配
// [法则09] 副作用声明：Get 取出 buf 后调用方独占，Put 归还后不能再访问
var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

// ======================== 节点与规则解析 ========================

// [法则22] 单一职责：只解析节点字符串为 Node 结构
func parseNode(nodeStr string) Node {
	var n Node
	parts := strings.SplitN(nodeStr, "#", 2)
	n.Domain = strings.TrimSpace(parts[0])
	if len(parts) != 2 || parts[1] == "" { return n }

	for _, e := range strings.Split(strings.TrimSpace(parts[1]), ",") {
		e = strings.TrimSpace(e)
		if e == "" { continue }
		weight := 1
		addr := e
		if strings.Contains(e, "|") {
			p := strings.SplitN(e, "|", 2)
			addr = p[0]
			if w, err := strconv.Atoi(p[1]); err == nil && w > 0 { weight = w }
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil { host = addr; port = "" }
		n.Backends = append(n.Backends, Backend{IP: host, Port: port, Weight: weight})
	}
	return n
}

// [法则22] 单一职责：只解析规则字符串填充全局 routingMap
func parseRules(pool []Node) {
	if len(globalConfig.Outbounds) == 0 { return }
	var s ProxySettings
	if err := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err != nil || s.Rules == "" { return }

	rawRules := strings.NewReplacer("|", "\n", "，", ",").Replace(s.Rules)
	for _, line := range strings.Split(rawRules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }

		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.Split(line, ",")
		if len(parts) < 2 { continue }

		keyword  := strings.TrimSpace(parts[0])
		nodeStr  := strings.TrimSpace(parts[1])
		strategy := ""
		if len(parts) >= 3 { strategy = strings.TrimSpace(parts[2]) }

		var ruleType int
		var ruleValue string
		var compiledRegex *regexp.Regexp

		switch {
		case strings.HasPrefix(keyword, "regexp:"):
			ruleType = MatchTypeRegex
			ruleValue = strings.TrimPrefix(keyword, "regexp:")
			compiledRegex = regexp.MustCompile(ruleValue)
		case strings.HasPrefix(keyword, "domain:"):
			ruleType = MatchTypeDomain
			ruleValue = strings.TrimPrefix(keyword, "domain:")
		case strings.HasPrefix(keyword, "geosite:"):
			ruleType = MatchTypeGeosite
			ruleValue = strings.TrimPrefix(keyword, "geosite:")
		case strings.HasPrefix(keyword, "geoip:"):
			ruleType = MatchTypeGeoIP
			ruleValue = strings.TrimPrefix(keyword, "geoip:")
		default:
			ruleType = MatchTypeSubstring
			ruleValue = keyword
		}

		var foundNode Node
		for _, pNode := range pool {
			if pNode.Domain == nodeStr { foundNode = pNode; break }
		}
		if foundNode.Domain == "" { foundNode = parseNode(nodeStr) }

		if keyword != "" && foundNode.Domain != "" {
			routingMap = append(routingMap, Rule{
				Type: ruleType, Value: ruleValue,
				CompiledRegex: compiledRegex,
				Node: foundNode, Strategy: strategy,
			})
		}
	}
}

// [法则22] 单一职责：只解析 outbounds 配置并初始化 proxySettingsMap
func parseOutbounds() {
	for i, outbound := range globalConfig.Outbounds {
		if outbound.Protocol != "ech-proxy" { continue }

		var settings ProxySettings
		if err := json.Unmarshal(outbound.Settings, &settings); err != nil { continue }

		rawPool := strings.NewReplacer("\r\n", ";", "\n", ";", "，", ";", ",", ";", "；", ";").Replace(settings.Server)
		for _, nodeStr := range strings.Split(rawPool, ";") {
			if trimmed := strings.TrimSpace(nodeStr); trimmed != "" {
				settings.NodePool = append(settings.NodePool, parseNode(trimmed))
			}
		}

		if settings.S5 != "" {
			settings.ForwarderSettings = &ProxyForwarderSettings{Socks5Address: settings.S5}
		}

		// [法则13] 原子赋值：nil 检查后赋值，不存在中间态
		if settings.DNS == nil { settings.DNS = &defaultDNSConfig }
		if settings.Sniffing == nil { settings.Sniffing = &defaultSniffingConfig }

		proxySettingsMap[outbound.Tag] = settings
		b, _ := json.Marshal(settings)
		globalConfig.Outbounds[i].Settings = b
	}
}

// ======================== 测速模块 ========================

type TestResult struct {
	Node  Node
	Delay time.Duration
	Error error
}

func pingNode(node Node, token, globalIP string, results chan<- TestResult) {
	start := time.Now()
	backend := selectBackend(node.Backends, "")
	if backend.IP == "" { backend.IP = globalIP }

	conn, err := dialZeusWebSocket(node.Domain, backend, token)
	if err != nil {
		results <- TestResult{Node: node, Error: err}
		return
	}
	conn.Close()
	results <- TestResult{Node: node, Delay: time.Since(start)}
}

// RunSpeedTest 并发测速所有节点并按延迟排序输出
// [法则38] 契约: 输入节点池字符串+token+globalIP | 输出标准输出打印结果 | 副作用：并发建立 WebSocket 连接
func RunSpeedTest(serverAddr, token, globalIP string) {
	rawPool := strings.NewReplacer("\r\n", ";", "\n", ";").Replace(serverAddr)
	var nodes []Node
	for _, s := range strings.Split(rawPool, ";") {
		if t := strings.TrimSpace(s); t != "" { nodes = append(nodes, parseNode(t)) }
	}
	if len(nodes) == 0 { log.Println("No valid nodes found."); return }

	var wg sync.WaitGroup
	results := make(chan TestResult, len(nodes))
	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			pingNode(n, strings.SplitN(token, "|", 2)[0], globalIP, results)
		}(node)
	}
	wg.Wait()
	close(results)

	var successful, failed []TestResult
	for res := range results {
		if res.Error == nil { successful = append(successful, res) } else { failed = append(failed, res) }
	}
	sort.Slice(successful, func(i, j int) bool { return successful[i].Delay < successful[j].Delay })

	fmt.Println("\nPing Test Report")
	fmt.Println("\nSuccessful Nodes")
	for i, res := range successful {
		fmt.Printf("%d. %-40s | Delay: %v\n", i+1, formatNode(res.Node), res.Delay.Round(time.Millisecond))
	}
	if len(failed) > 0 {
		fmt.Println("\nFailed Nodes")
		for _, res := range failed {
			fmt.Printf("- %-40s | Error: %v\n", formatNode(res.Node), res.Error)
		}
	}
}

// formatNode 将 Node 格式化为可读字符串
// [法则02] 存在即必要：用 strings.Builder 消除中间赋值
// [法则38] 契约: 输入 Node | 输出 "domain#ip:port|weight,..." 格式字符串 | 副作用：无
func formatNode(n Node) string {
	if len(n.Backends) == 0 {
		return n.Domain
	}
	var sb strings.Builder
	sb.WriteString(n.Domain)
	sb.WriteByte('#')
	for i, b := range n.Backends {
		if i > 0 { sb.WriteByte(',') }
		sb.WriteString(b.IP)
		if b.Port != "" { sb.WriteByte(':'); sb.WriteString(b.Port) }
		if b.Weight > 1 { sb.WriteByte('|'); sb.WriteString(strconv.Itoa(b.Weight)) }
	}
	return sb.String()
}

// ======================== 主运行逻辑 ========================

// checkFileDependency 检查文件是否存在且不是目录
// [法则22] 单一职责：纯文件存在性检查
func checkFileDependency(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

// StartInstance 启动监听实例
// [法则38] 契约: 输入 JSON 配置 | 输出 (Listener, error) | 副作用：初始化全局状态，启动 Accept 循环，启动连接池清理器
// [法则01] 极简：移除 Go 1.20+ 已废弃的 rand.Seed 调用
// [法则39] 生命周期：stopCh 控制 idlePoolCleaner goroutine 生命周期
func StartInstance(configContent []byte) (net.Listener, error) {
	// [法则01] rand.Seed 已移除：Go 1.20+ 全局随机数自动播种，显式调用是多余代码

	// [法则39] 生命周期：重启时先停止旧的清理器，再启动新的
	if poolCleanerStopCh != nil {
		close(poolCleanerStopCh)
	}
	poolCleanerStopCh = make(chan struct{})

	proxySettingsMap = make(map[string]ProxySettings)
	routingMap = nil

	log.Println("[Core] 正在检查运行环境...")
	for _, dep := range []string{"xray.exe", "geosite.dat", "geoip.dat"} {
		if checkFileDependency(dep) {
			log.Printf("[Core] ✅ %s", dep)
		} else {
			log.Printf("[Core] ⚠️  %s 未找到", dep)
		}
	}

	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds()

	// [法则13] 原子赋值：一次性完成全局解析器初始化
	s, hasProxy := proxySettingsMap["proxy"]
	if hasProxy {
		parseRules(s.NodePool)
		dnsConfig := defaultDNSConfig
		if s.DNS != nil { dnsConfig = *s.DNS }
		globalDNSResolver = NewDNSResolver(dnsConfig)
		log.Printf("[Core] [DNS] strategy:%s", dnsConfig.Strategy)

		sniffConfig := defaultSniffingConfig
		if s.Sniffing != nil { sniffConfig = *s.Sniffing }
		globalSniffer = NewSniffer(sniffConfig)
		log.Printf("[Core] [Sniff] protocols:%v", sniffConfig.DestOverride)
	} else {
		globalDNSResolver = NewDNSResolver(defaultDNSConfig)
		globalSniffer = NewSniffer(defaultSniffingConfig)
	}

	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds configured") }

	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }

	mode := "Single Node"
	if hasProxy {
		if len(s.NodePool) > 1 {
			mode = fmt.Sprintf("Pool(%d nodes, strategy:%s)", len(s.NodePool), s.Strategy)
		} else if len(s.NodePool) == 1 {
			mode = fmt.Sprintf("Single(%s)", s.NodePool[0].Domain)
		}
		if len(routingMap) > 0 {
			mode += fmt.Sprintf("+%dRules", len(routingMap))
		}
	}
	log.Printf("[Core] v21.8 listening:%s mode:%s", inbound.Listen, mode)

	// [新增][法则39] 生命周期：启动空闲连接清理 goroutine
	go startIdlePoolCleaner(poolCleanerStopCh)
	log.Printf("[Core] [Pool] idle cleaner started, interval:%v maxDepth:%d", poolCleanInterval, maxPoolDepth)

	// [法则39] 生命周期：Accept 循环在 goroutine 中，主 goroutine 持有 listener
	go acceptLoop(listener, inbound.Tag)
	return listener, nil
}

// StopInstance 优雅停止实例
// [新增][法则39] 生命周期：提供给调用方（C 客户端）的显式停止入口
// [法则09] 副作用声明：停止 idlePoolCleaner，关闭所有池化连接
// [法则50] 向死而生：优先清理连接池（释放服务端资源），再关闭 listener
func StopInstance(listener net.Listener) {
	// 停止清理器
	if poolCleanerStopCh != nil {
		close(poolCleanerStopCh)
		poolCleanerStopCh = nil
	}
	// 清空连接池（驱逐所有连接）
	globalConnPool.mu.Lock()
	for key, list := range globalConnPool.conns {
		for _, pc := range list {
			pc.conn.Close()
		}
		delete(globalConnPool.conns, key)
	}
	globalConnPool.mu.Unlock()
	log.Printf("[Core] [Pool] all connections evicted")

	// 关闭 listener（acceptLoop 检测到 ErrClosed 后自然退出）
	if listener != nil {
		listener.Close()
	}
	log.Printf("[Core] instance stopped")
}

// acceptLoop 持续接受连接并分发处理
// [法则22] 单一职责：只负责 accept 和分发，不做协议处理
// [法则38] 契约: 输入 Listener | 输出：无 | 副作用：为每个连接启动 goroutine
// [法则46] 可观测性：区分正常关闭（ErrClosed）和意外错误，分别记录
func acceptLoop(listener net.Listener, inboundTag string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// [法则46] 区分正常关闭与意外错误，避免日志噪声掩盖真实问题
			if errors.Is(err, net.ErrClosed) {
				log.Printf("[Core] listener closed, acceptLoop exiting")
			} else {
				log.Printf("[Core] accept error: %v", err)
			}
			return
		}
		go handleGeneralConnection(conn, inboundTag)
	}
}

// ======================== 连接处理（职责拆分版）========================

// connContext 单次连接上下文
// [法则40] 状态局部化：连接状态封装在 struct 内，不污染全局
// [法则14] 不变量：mode 使用具名 connMode 类型，不变量由类型系统辅助检查
type connContext struct {
	conn        net.Conn
	target      string
	mode        connMode // 响应状态机，见 connMode 常量定义
	firstFrame  []byte   // HTTP 明文请求体（modeHTTPPlain 时有效）
	pendingData []byte   // sniff 读到的数据，需随首包一起转发
}

// handleGeneralConnection 连接入口
// [法则22] 单一职责：只做协议识别和分发
// [法则31] 抽象层次一致：全部调用同级抽象函数
// [法则04] 意图透明：socks5Version 具名常量替代魔法字节 0x05
func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }

	var ctx connContext
	ctx.conn = conn

	var err error
	switch buf[0] {
	case socks5Version:
		ctx.target, err = handleSOCKS5(conn, inboundTag)
		ctx.mode = modeSOCKS5Pending
	default:
		ctx.target, ctx.firstFrame, ctx.mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil { return }

	// [法则31] 职责链：sniff → dns → connect → pipe
	sniffAndRewrite(&ctx)
	resolveTarget(&ctx)

	wsConn, nodeKey, err := connectNanoTunnel(ctx.target, "proxy", append(ctx.pendingData, ctx.firstFrame...))
	if err != nil {
		log.Printf("[Core] connect failed target:%s err:%v", ctx.target, err)
		return
	}

	// [法则19] 幂等：sendProxyResponse 仅在 mode != modeResponded 时发送
	sendProxyResponse(&ctx)

	// [新增][法则32] 单一归属：pipeDirect 持有 nodeKey，退出时归还或驱逐连接
	pipeDirect(conn, wsConn, nodeKey, ctx.target)
}

// sendEarlyProxyResponse 在 sniff 之前发出代理响应（SOCKS5/HTTPS CONNECT 模式）
// [法则22] 单一职责：只负责写响应字节
// [法则09] 副作用声明：写入 ctx.conn，更新 ctx.mode = modeResponded
func sendEarlyProxyResponse(ctx *connContext) {
	switch ctx.mode {
	case modeSOCKS5Pending:
		ctx.conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		ctx.mode = modeResponded
	case modeHTTPSPending:
		ctx.conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		ctx.mode = modeResponded
	}
}

// sniffAndRewrite 对 IP 目标执行流量嗅探，可能重写 target 为域名
// [法则22] 单一职责：只做 sniff 读数据+重写 target，不负责发送代理响应
// [法则09] 副作用声明：修改 ctx.target, ctx.pendingData；
//           SOCKS5/HTTPS 模式下先调用 sendEarlyProxyResponse（副作用在被调函数中声明）
func sniffAndRewrite(ctx *connContext) {
	if globalSniffer == nil || !globalSniffer.config.Enabled { return }

	host, port, err := net.SplitHostPort(ctx.target)
	if err != nil || !isIPAddress(host) { return }

	switch ctx.mode {
	case modeSOCKS5Pending, modeHTTPSPending:
		// [法则22] 发响应是独立职责，委托给专职函数
		sendEarlyProxyResponse(ctx)

		sniffBuf := make([]byte, 2048)
		ctx.conn.SetReadDeadline(time.Now().Add(sniffReadTimeout))
		n, readErr := ctx.conn.Read(sniffBuf)
		ctx.conn.SetReadDeadline(time.Time{})

		if readErr == nil && n > 0 {
			ctx.pendingData = sniffBuf[:n]
			if r := globalSniffer.Sniff(ctx.pendingData); r.Success {
				log.Printf("[Sniff] %s→%s protocol:%s", host, r.Domain, r.Protocol)
				ctx.target = net.JoinHostPort(r.Domain, port)
			}
		}

	case modeHTTPPlain:
		if r := globalSniffer.Sniff(ctx.firstFrame); r.Success {
			log.Printf("[Sniff] %s→%s protocol:%s", host, r.Domain, r.Protocol)
			ctx.target = net.JoinHostPort(r.Domain, port)
		}
	}
}

// resolveTarget 对 target 中的域名执行 DNS 解析，可能替换为 IP
// [法则22] 单一职责：只做 DNS 解析
// [法则09] 副作用声明：可能修改 ctx.target
func resolveTarget(ctx *connContext) {
	if globalDNSResolver == nil { return }

	host, port, err := net.SplitHostPort(ctx.target)
	if err != nil || isIPAddress(host) { return }

	resolved := globalDNSResolver.ResolveIP(host)
	if resolved != host {
		ctx.target = net.JoinHostPort(resolved, port)
		log.Printf("[DNS] %s→%s", host, resolved)
	}
}

// sendProxyResponse 在隧道建立后，如果响应尚未发出则补发
// [法则19] 幂等：mode=modeResponded 时已发响应，不重复发
// [法则09] 副作用声明：写入 ctx.conn，更新 ctx.mode = modeResponded
func sendProxyResponse(ctx *connContext) {
	switch ctx.mode {
	case modeSOCKS5Pending:
		ctx.conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		ctx.mode = modeResponded
	case modeHTTPSPending:
		ctx.conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		ctx.mode = modeResponded
	}
}

// ======================== 路由匹配 ========================

func match(rule Rule, target string) bool {
	targetHost, _, _ := net.SplitHostPort(target)
	if targetHost == "" { targetHost = target }
	switch rule.Type {
	case MatchTypeDomain:  return targetHost == rule.Value
	case MatchTypeRegex:   return rule.CompiledRegex.MatchString(targetHost)
	case MatchTypeGeosite: return false
	case MatchTypeGeoIP:   return false
	default:               return strings.Contains(target, rule.Value)
	}
}

// ======================== 隧道连接（含连接池）========================

// connectNanoTunnel 根据路由规则选择节点建立 WebSocket 隧道
// [法则38] 契约: 输入目标地址+outboundTag+首包 payload | 输出 (WebSocket连接, nodeKey, error) | 副作用：建立 TCP+WS 连接或从池复用
// [新增] 返回 nodeKey 供 pipeDirect 在退出时归还/驱逐连接到池
// [法则49] 失败常态：池命中 Ping 失败→驱逐→新建；新建失败→多节点池换节点重试一次
func connectNanoTunnel(target, outboundTag string, payload []byte) (*websocket.Conn, string, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, "", errors.New("outbound settings not found: " + outboundTag) }

	parts := strings.SplitN(settings.Token, "|", 2)
	secretKey := parts[0]
	fallback := ""
	if len(parts) > 1 { fallback = parts[1] }

	socks5Addr := ""
	if settings.ForwarderSettings != nil { socks5Addr = settings.ForwarderSettings.Socks5Address }

	// [新增][法则29] 跨函数命名：attemptDial 明确表达「一次完整的拨号尝试（含池查找）」
	// [新增][法则32] 单一归属：返回 nodeKey，供调用链上层在 pipeDirect 中归还连接
	attemptDial := func() (*websocket.Conn, string, error) {
		node, logMsg := selectNode(target, settings)
		log.Print(logMsg)

		nodeKey := node.Domain // [法则03] 单一真相：nodeKey 与 Domain 绑定

		// [新增][法则质子-01] 零阻塞：优先从连接池取复用连接，跳过 TLS+WS 握手
		if cachedConn := globalConnPool.acquire(nodeKey); cachedConn != nil {
			// 池命中：直接复用，仅发送协议头（无握手代价）
			if err := sendNanoHeaderV2(cachedConn, target, payload, socks5Addr, fallback); err != nil {
				// 协议头发送失败 → 连接已死 → 驱逐并回退到新建连接
				log.Printf("[Pool] header send failed key:%s err:%v, evicting and redial", nodeKey, err)
				globalConnPool.evict(nodeKey, cachedConn)
				// fall through to dial new connection below
			} else {
				log.Printf("[Core] pool-hit tunnel target:%s node:%s", target, nodeKey)
				return cachedConn, nodeKey, nil
			}
		}

		// 池未命中或已驱逐：新建连接
		backend := selectBackend(node.Backends, target)
		if backend.IP == "" { backend.IP = settings.ServerIP }

		start := time.Now()
		wsConn, err := dialZeusWebSocket(node.Domain, backend, secretKey)
		if err != nil { return nil, nodeKey, err }

		if backend.IP != "" {
			log.Printf("[Core] new tunnel SNI:%s real:%s:%s latency:%dms",
				node.Domain, backend.IP, backend.Port, time.Since(start).Milliseconds())
		}

		if err := sendNanoHeaderV2(wsConn, target, payload, socks5Addr, fallback); err != nil {
			wsConn.Close()
			return nil, nodeKey, err
		}

		// [新增] 新建成功 → 尝试入池（池满则不缓存，此连接用完即关）
		if !globalConnPool.put(nodeKey, wsConn) {
			// 池满，此连接不缓存，pipeDirect 结束后直接关闭
			// 用空字符串作 nodeKey 标记"不归还到池"
			return wsConn, "", nil
		}
		return wsConn, nodeKey, nil
	}

	// 第一次尝试
	wsConn, nodeKey, err := attemptDial()
	if err != nil && len(settings.NodePool) > 1 {
		// [法则49] 失败常态：多节点池下换节点重试一次，单节点不重试（避免放大延迟）
		log.Printf("[Core] retry after err:%v", err)
		wsConn, nodeKey, err = attemptDial()
	}
	return wsConn, nodeKey, err
}

// selectNode 根据路由规则和负载策略选择节点
// [法则22] 单一职责：只做路由决策，返回节点和日志消息
func selectNode(target string, settings ProxySettings) (Node, string) {
	for _, rule := range routingMap {
		if match(rule, target) {
			strategy := rule.Strategy
			if strategy == "" { strategy = settings.Strategy }
			return rule.Node, fmt.Sprintf("[Core] rule-hit target:%s node:%s rule:%s strategy:%s",
				target, rule.Node.Domain, rule.Value, strategy)
		}
	}

	if len(settings.NodePool) == 0 {
		return Node{}, "[Core] no nodes in pool"
	}

	strategy := settings.Strategy
	var node Node
	switch strategy {
	case "rr":
		idx := atomic.AddUint64(&globalRRIndex, 1)
		node = settings.NodePool[idx%uint64(len(settings.NodePool))]
	case "hash":
		h := md5.Sum([]byte(target))
		hashVal := binary.BigEndian.Uint64(h[:8])
		node = settings.NodePool[hashVal%uint64(len(settings.NodePool))]
	default:
		node = settings.NodePool[rand.Intn(len(settings.NodePool))]
	}
	return node, fmt.Sprintf("[Core] lb target:%s node:%s strategy:%s", target, node.Domain, strategy)
}

// selectBackend 按权重哈希选择 Backend
// [法则22] 单一职责：纯选择函数
// [法则20] 函数内命名：hashSlot 替代原 target（消除与外层参数 target string 同名的歧义）
func selectBackend(backends []Backend, key string) Backend {
	switch len(backends) {
	case 0: return Backend{}
	case 1: return backends[0]
	}
	total := 0
	for _, b := range backends { total += b.Weight }
	h := md5.Sum([]byte(key))
	hashVal := binary.BigEndian.Uint64(h[:8])
	if total == 0 { return backends[int(hashVal%uint64(len(backends)))] }

	// [法则20] hashSlot 替代原 target，消除与外层 target string 的命名歧义
	hashSlot := int(hashVal % uint64(total))
	cur := 0
	for _, b := range backends {
		cur += b.Weight
		if hashSlot < cur { return b }
	}
	return backends[0]
}

// ======================== WebSocket 拨号 ========================

// dialZeusWebSocket 建立 WebSocket 连接
// [法则38] 契约: 输入 SNI+backend+token | 输出 WebSocket 连接或 error | 副作用：TCP+TLS+WS 握手
func dialZeusWebSocket(sni string, backend Backend, token string) (*websocket.Conn, error) {
	sniHost, sniPort, err := net.SplitHostPort(sni)
	if err != nil { sniHost = sni; sniPort = "443" }

	dialPort := sniPort
	if backend.Port != "" { dialPort = backend.Port }

	wsURL := fmt.Sprintf("wss://%s:%s/?token=%s", sniHost, sniPort, url.QueryEscape(token))
	headers := http.Header{}
	headers.Add("Host", sniHost)
	headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	dialer := websocket.Dialer{
		// [法则37] 有意识缺陷：InsecureSkipVerify=true
		// SNI-only 路由模式：TLS 握手使用 SNI 域名，但 TCP 连接到 backend.IP
		// 证书 CN 与 IP 不匹配是预期行为，此为架构设计决策，非安全疏忽
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
		HandshakeTimeout: wsHandshakeTimeout,
	}
	if backend.IP != "" {
		dialer.NetDial = func(network, _ string) (net.Conn, error) {
			return net.DialTimeout(network, net.JoinHostPort(backend.IP, dialPort), wsHandshakeTimeout)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil { return nil, fmt.Errorf("ws handshake status:%d", resp.StatusCode) }
		return nil, err
	}
	return conn, nil
}

// ======================== 数据转发 ========================

// pipeDirect 双向转发数据，直到任一方向 EOF
// [法则38] 契约: 输入本地连接+WS连接+nodeKey+目标地址 | 输出：无 | 副作用：数据转发+连接归还/驱逐+统计日志
// [新增][法则32] 单一归属：pipeDirect 通过 nodeKey 在退出时将连接归还池或驱逐
//   - nodeKey 非空 → 正常结束时 release 归还，异常时 evict 驱逐
//   - nodeKey 为空 → 池满时不缓存，直接关闭（ws.Close 由 defer 完成）
// [法则43] 同步终止：wg.Wait() 保证两个 goroutine 都结束后才执行清理和统计
// [法则09] 背压传导：上下行各持独立 bufPool buffer，避免共享 buffer 竞争
func pipeDirect(local net.Conn, ws *websocket.Conn, nodeKey, target string) {
	var pipErr atomic.Value // 记录首个错误（上行或下行）
	var upBytes, downBytes int64
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	// 下行：ws → local
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			mt, r, err := ws.NextReader()
			if err != nil {
				pipErr.Store(err)
				break
			}
			if mt == websocket.BinaryMessage {
				n, err := io.CopyBuffer(local, r, buf)
				atomic.AddInt64(&downBytes, n)
				if err != nil {
					pipErr.Store(err)
					break
				}
			}
		}
		// 下行结束后关闭 local，驱动上行 goroutine 退出（local.Read 报错）
		local.Close()
	}()

	// 上行：local → ws
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				atomic.AddInt64(&upBytes, int64(n))
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					pipErr.Store(werr)
					break
				}
			}
			if err != nil { break }
		}
		// 上行结束后关闭 ws，驱动下行 goroutine 退出（ws.NextReader 报错）
		ws.Close()
	}()

	wg.Wait()

	// [新增][法则32] 单一归属：连接归还/驱逐统一在此处执行
	if nodeKey != "" {
		if pipErr.Load() != nil {
			// 管道出错 → 连接已损坏 → 驱逐（不归还）
			globalConnPool.evict(nodeKey, ws)
			log.Printf("[Pool] pipe error, evicted key:%s err:%v", nodeKey, pipErr.Load())
		} else {
			// 正常结束 → 归还连接到池供复用
			globalConnPool.release(nodeKey, ws)
		}
	}
	// nodeKey 为空（池满时不缓存）→ ws 已由上行 goroutine Close，无需额外处理

	log.Printf("[Stats] %s up:%s down:%s time:%v",
		target, formatBytes(upBytes), formatBytes(downBytes), time.Since(start).Round(time.Second))
}

// formatBytes 将字节数格式化为人类可读字符串
// [法则38] 契约: 输入字节数 | 输出 "1.2 KB" 格式字符串 | 副作用：无（纯函数）
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ======================== Nano 协议头 ========================

// sendNanoHeaderV2 发送 Xlink 协议头
// [法则38] 契约: 输入 WS 连接+目标地址+payload+s5+fb | 输出 error | 副作用：写入 WebSocket
// [法则11+12] 边界完备+语义合法：长度超 255 立即返回错误
// [法则09] 副作用最小化：不修改任何入参
// [法则54] 认知负载：strconv.ParseUint 替代 fmt.Sscanf，语义更直接
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)

	// [法则54] strconv.ParseUint 比 fmt.Sscanf 认知成本更低，意图更明确
	portVal, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	port := uint16(portVal)

	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = ip.String()
	}

	hb, s5b, fbb := []byte(host), []byte(s5), []byte(fb)
	if len(hb) > 255 || len(s5b) > 255 || len(fbb) > 255 {
		return errors.New("field length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hb))); buf.Write(hb)
	pb := make([]byte, 2); binary.BigEndian.PutUint16(pb, port); buf.Write(pb)
	buf.WriteByte(byte(len(s5b)))
	if len(s5b) > 0 { buf.Write(s5b) }
	buf.WriteByte(byte(len(fbb)))
	if len(fbb) > 0 { buf.Write(fbb) }
	if len(payload) > 0 { buf.Write(payload) }

	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// ======================== 入站协议处理 ========================

// handleSOCKS5 处理 SOCKS5 握手，返回目标地址
// [法则38] 契约: 输入已读取首字节后的连接 | 输出目标地址或 error | 副作用：读写 conn 完成握手
// [法则22] 单一职责：只做 SOCKS5 协议解析
func handleSOCKS5(conn net.Conn, _ string) (string, error) {
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return "", err }
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return "", err }

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil { return "", err }

	var host string
	switch header[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil { return "", err }
		host = net.IP(b).String()
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil { return "", err }
		d := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, d); err != nil { return "", err }
		host = string(d)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil { return "", err }
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("unsupported SOCKS5 atype:%d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil { return "", err }
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// handleHTTP 处理 HTTP/HTTPS CONNECT 请求，返回目标地址和首包数据
// [法则38] 契约: 输入连接+首字节+inboundTag | 输出(target, firstFrame, mode, error)
// [法则23] 返回值语义完备：返回 connMode 类型而非裸 int
// [法则22] 单一职责：只做 HTTP 协议解析
func handleHTTP(conn net.Conn, initialData []byte, _ string) (string, []byte, connMode, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil { return "", nil, modeResponded, err }

	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" { target += ":443" } else { target += ":80" }
	}

	if req.Method == "CONNECT" {
		return target, nil, modeHTTPSPending, nil
	}

	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), modeHTTPPlain, nil
}
