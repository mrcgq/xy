// cmd/xlink-cli/main.go (Final Fix v7.3)

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	// 【关键修正 1】确保 import 路径与你的 go.mod 文件匹配
	// 根据你的 GitHub 仓库地址，应该是这个
	"github.com/mrcgq/xy/core" 
)

func main() {
    // 【关键修正 2】移除无用的 configFile 变量
    // configFile := flag.String("c", "config.json", "Path to config file") // DELETED

    // 定义所有需要的命令行参数
    serverAddr := flag.String("server", "", "Server address")
    serverIP := flag.String("ip", "", "Specific server IP")
    secretKey := flag.String("key", "", "Secret key for authentication")
    socks5Addr := flag.String("s5", "", "SOCKS5 proxy address")
    fallbackAddr := flag.String("fallback", "", "Fallback address")
    listenAddr := flag.String("listen", "127.0.0.1:10808", "Local listen address")

	flag.Parse()

    // 动态生成 JSON 配置
	configJSON := core.GenerateConfigJSON(*serverAddr, *serverIP, *secretKey, *socks5Addr, *fallbackAddr, *listenAddr)

	log.Println("[CLI] Starting X-Link Unified Ghost Core Engine...")
    
    // 【关键修正 3】确保函数调用正确
	listener, err := core.StartInstance([]byte(configJSON))
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Println("[CLI] Engine running successfully.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
