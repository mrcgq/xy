// cmd/xlink-cli/main.go (Final Fix v7.3)

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	// ⚠️ 注意：请确保 go.mod 文件中的 module 名称与此处一致
	// 如果本地开发报错，请检查 go.mod 第一行是否为 module github.com/mrcgq/xy
	"github.com/mrcgq/xy/core" 
)

func main() {
	// 定义命令行参数 (与 C 客户端 v8.2 的调用参数对应)
	serverAddr := flag.String("server", "", "Server address (e.g. cdn.worker.dev:443)")
	serverIP := flag.String("ip", "", "Specific server IP")
	secretKey := flag.String("key", "", "Secret key for authentication")
	socks5Addr := flag.String("s5", "", "SOCKS5 proxy address")
	fallbackAddr := flag.String("fallback", "", "Fallback address")
	listenAddr := flag.String("listen", "127.0.0.1:10808", "Local listen address")

	flag.Parse()

	// [新增] 基础参数校验
	if *serverAddr == "" {
		log.Fatal("[CLI] Error: --server argument is required. (e.g. --server=cdn.worker.dev:443)")
	}

	// 动态生成 JSON 配置
	configJSON := core.GenerateConfigJSON(*serverAddr, *serverIP, *secretKey, *socks5Addr, *fallbackAddr, *listenAddr)

	log.Println("[CLI] Starting X-Link Unified Ghost Core Engine (v7.3 Binary)...")

	// 启动核心
	listener, err := core.StartInstance([]byte(configJSON))
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Printf("[CLI] Engine running successfully on %s", *listenAddr)

	// 优雅退出处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
