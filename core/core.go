// core/core.go (v3.1 - SOCKS5 fix) 内核文件
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
	"golang.org/x/net/proxy" // [修复] 导入 SOCKS5 代理库
)

// ======================== Structs (已修复) ========================
type JsonEnvelope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	TS   int64  `json:"ts"`
	Data string `json:"data"`
}
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

// [修复] 增加用于解析 SOCKS5 设置的结构体
type ProxyForwarderSettings struct {
	Socks5Address string `json:"socks5_address"`
}

// [修复] 修改 ProxySettings 结构体以包含可选的 SOCKS5 设置
type ProxySettings struct {
	Server          string                  `json:"server"`
	ServerIP        string                  `json:"server_ip"`
	Token           string                  `json:"token"`
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
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
)

// ======================== Helpers ========================
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
		return nil, err
	}
	if envelope.Type == "pong" {
		return nil, nil
	}
	if envelope.Type != "sync_data" {
		return nil, errors.New("not sync_data")
	}
	return base64.StdEncoding.DecodeString(envelope.Data)
}

// ======================== Entry Point ========================
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds")
	}
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, err
	}
	log.Printf("[Core] Titan Engine v3.1 Listening on %s", inbound.Listen)
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
	var mode int

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}

	if err != nil {
		return
	}

	wsConn, proto, err := tryConnect(target, "proxy", firstFrame, true)
	if err != nil {
		wsConn, proto, err = tryConnect(target, "proxy", firstFrame, false)
		if err != nil {
			log.Printf("[ERROR] Connection to %s failed after all attempts: %v", target, err)
			return
		}
	}

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	if proto == "binary" {
		pipeBinary(conn, wsConn)
	} else {
		pipeJSON(conn, wsConn)
	}
}

// ======================== Protocol Handlers ========================

func tryConnect(target, outboundTag string, firstFrame []byte, useBinary bool) (*websocket.Conn, string, error) {
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		return nil, "", err
	}

	wsConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	defer wsConn.SetReadDeadline(time.Time{})

	if useBinary {
		var buf bytes.Buffer
		buf.Write([]byte{0x01, 0x01})
		host, portStr, _ := net.SplitHostPort(target)
		portInt, _ := net.LookupPort("tcp", portStr)
		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x03)
			buf.WriteByte(byte(len(host)))
			buf.WriteString(host)
		}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(portInt))
		buf.Write(portBytes)
		if len(firstFrame) > 0 {
			buf.Write(firstFrame)
		}

		if err := wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil {
			wsConn.Close()
			return nil, "", err
		}
		_, msg, err := wsConn.ReadMessage()
		if err != nil {
			wsConn.Close()
			return nil, "", err
		}
		if len(msg) < 2 || msg[0] != 0x01 || msg[1] != 0x00 {
			wsConn.Close()
			return nil, "", fmt.Errorf("rejected")
		}
		return wsConn, "binary", nil

	} else {
		connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
		jsonHandshake, _ := wrapAsJson([]byte(connectMsg))
		if err := wsConn.WriteMessage(websocket.TextMessage, jsonHandshake); err != nil {
			wsConn.Close()
			return nil, "", err
		}
		_, msg, err := wsConn.ReadMessage()
		if err != nil {
			wsConn.Close()
			return nil, "", err
		}
		okPayload, err := unwrapFromJson(msg)
		if err != nil || string(okPayload) != "X-LINK-OK" {
			wsConn.Close()
			return nil, "", fmt.Errorf("rejected")
		}
		return wsConn, "json", nil
	}
}

func pipeBinary(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	go func() {
		for {
			mt, r, err := ws.NextReader()
			if err != nil {
				break
			}
			if mt == websocket.BinaryMessage {
				io.Copy(local, r)
			}
		}
		local.Close()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			w, err := ws.NextWriter(websocket.BinaryMessage)
			if err != nil {
				break
			}
			w.Write(buf[:n])
			w.Close()
		}
		if err != nil {
			break
		}
	}
}

func pipeJSON(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	go func() {
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				break
			}
			payload, _ := unwrapFromJson(msg)
			if payload != nil {
				local.Write(payload)
			}
		}
		local.Close()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			jsonData, _ := wrapAsJson(buf[:n])
			ws.WriteMessage(websocket.TextMessage, jsonData)
		}
		if err != nil {
			break
		}
	}
}

// ======================== Utils ========================
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2)
	io.ReadFull(conn, handshakeBuf)
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4)
	io.ReadFull(conn, header)
	var host string
	switch header[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 3:
		b := make([]byte, 1)
		io.ReadFull(conn, b)
		d := make([]byte, b[0])
		io.ReadFull(conn, d)
		host = string(d)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
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

// [已修复] dialSpecificWebSocket 函数现在支持通过 SOCKS5 代理进行连接
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("settings not found for outbound tag: " + outboundTag)
	}

	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	requestHeader := http.Header{}
	requestHeader.Add("Host", host)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: host},
		HandshakeTimeout: 20 * time.Second,
	}

	// [修复] 检查是否存在 SOCKS5 代理配置
	if settings.ForwarderSettings != nil && settings.ForwarderSettings.Socks5Address != "" {
		log.Printf("[Core] Using SOCKS5 proxy: %s", settings.ForwarderSettings.Socks5Address)
		// 创建一个 SOCKS5 拨号器
		socks5Dialer, err := proxy.SOCKS5("tcp", settings.ForwarderSettings.Socks5Address, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		// 将 websocket 的拨号器替换为 SOCKS5 拨号器
		dialer.NetDial = socks5Dialer.Dial
	} else if settings.ServerIP != "" {
		// 如果没有 SOCKS5 代理但指定了 IP, 则使用 IP 直连
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	if settings.Token != "" {
		dialer.Subprotocols = []string{settings.Token}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
		}
		return nil, err
	}
	return conn, nil
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
