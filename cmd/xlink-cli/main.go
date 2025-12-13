// cmd/xlink-cli/main.go (v1.1 - Listen Port Support)
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"xlink-project/core"
)

func parseXlinkURI(uri string) ([]byte, error) {
	if !strings.HasPrefix(uri, "xlink://") {
		return nil, fmt.Errorf("invalid xlink uri scheme")
	}
	fakeURL := "http://" + uri[8:]
	parsed, err := url.Parse(fakeURL)
	if err != nil {
		return nil, err
	}
	
	token, _ := parsed.User.Password()
	if token == "" {
		token = parsed.User.Username()
	}
	server := parsed.Host
	queryParams := parsed.Query()
	secretKey := queryParams.Get("key")
	fallbackIP := queryParams.Get("fallback")
	serverIP := queryParams.Get("ip")
	
	// 【【【核心改动 1】】】 解析 listen 参数，并提供默认值
	listenAddr := queryParams.Get("listen")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080" // 如果 URI 中没有 listen 参数，则默认为 1080
	}

	// ... (Token 加密和 Config 构建逻辑保持不变) ...
	tokenPayload := map[string]interface{}{ "p":  token, "fb": fallbackIP, "ts": time.Now().Unix(), }
	payloadBytes, _ := json.Marshal(tokenPayload)
	if secretKey != "" { for i := 0; i < len(payloadBytes); i++ { payloadBytes[i] ^= secretKey[i%len(secretKey)] } }
	encodedToken := base64.StdEncoding.EncodeToString(payloadBytes)
	config := map[string]interface{}{
		"inbounds": []map[string]string{
			// 【【【核心改动 2】】】 使用从 URI 解析出的 listenAddr
			{"tag": "inbound-0", "listen": listenAddr, "protocol": "socks"},
		},
		"outbounds": []map[string]interface{}{
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "block", "protocol": "blackhole"},
			{ "tag": "proxy", "protocol": "ech-proxy", "settings": map[string]string{ "server": server, "server_ip": serverIP, "token": encodedToken, }, },
		},
		"routing": map[string]interface{}{ "rules": []interface{}{}, "defaultOutbound": "proxy", },
	}

	return json.MarshalIndent(config, "", "  ")
}

func main() {
    // main 函数完全保持不变
	uri := flag.String("uri", "", "xlink:// connection string")
	flag.Parse()
	if *uri == "" { log.Fatalf("Usage: %s -uri <xlink://...>", os.Args[0]) }
	log.Println("[CLI] Parsing URI and generating config...")
	configBytes, err := parseXlinkURI(*uri)
	if err != nil { log.Fatalf("[CLI] Failed to parse URI: %v", err) }
	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil { log.Fatalf("[CLI] Failed to start core engine: %v", err) }
	log.Println("[CLI] Engine running successfully.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("[CLI] Shutting down...")
	listener.Close()
}
