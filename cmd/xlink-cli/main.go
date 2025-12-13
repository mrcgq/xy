// cmd/xlink-cli/main.go
// 这是一个新的、独立的命令行客户端
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

	// 导入您刚刚创建的内核库
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
	// 兼容没有密码只有用户名的情况
	if token == "" {
		token = parsed.User.Username()
	}
	server := parsed.Host
	queryParams := parsed.Query()
	secretKey := queryParams.Get("key")
	fallbackIP := queryParams.Get("fallback")
	serverIP := queryParams.Get("ip")
	listenAddr := "127.0.0.1:1080" // 此处可硬编码，或未来通过命令行参数指定

	tokenPayload := map[string]interface{}{
		"p":  token,
		"fb": fallbackIP,
		"ts": time.Now().Unix(),
	}
	payloadBytes, _ := json.Marshal(tokenPayload)
	
	if secretKey != "" {
		for i := 0; i < len(payloadBytes); i++ {
			payloadBytes[i] ^= secretKey[i%len(secretKey)]
		}
	}
	encodedToken := base64.StdEncoding.EncodeToString(payloadBytes)

	config := map[string]interface{}{
		"inbounds": []map[string]string{
			{"tag": "inbound-0", "listen": listenAddr, "protocol": "socks"},
		},
		"outbounds": []map[string]interface{}{
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "block", "protocol": "blackhole"},
			{
				"tag":      "proxy",
				"protocol": "ech-proxy",
				"settings": map[string]string{
					"server":    server,
					"server_ip": serverIP,
					"token":     encodedToken,
				},
			},
		},
		"routing": map[string]interface{}{
			"rules":           []interface{}{},
			"defaultOutbound": "proxy",
		},
	}
	return json.MarshalIndent(config, "", "  ")
}

func main() {
	uri := flag.String("uri", "", "xlink:// connection string")
	flag.Parse()
	if *uri == "" {
		log.Fatalf("Usage: %s -uri <xlink://...>", os.Args[0])
	}
	log.Println("[CLI] Parsing URI and generating config...")
	configBytes, err := parseXlinkURI(*uri)
	if err != nil {
		log.Fatalf("[CLI] Failed to parse URI: %v", err)
	}
	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}
	log.Println("[CLI] Engine running successfully.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("[CLI] Shutting down...")
	listener.Close()
}
