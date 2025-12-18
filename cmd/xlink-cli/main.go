package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"xlink-project/core"
)

func main() {
    // 【修改点】不再使用 -c，而是直接接收 flag 参数
	configFile := flag.String("c", "config.json", "Path to config file") // 保留兼容性
	
    // 【新增】定义所有需要的命令行参数
    serverAddr := flag.String("server", "", "Server address")
    serverIP := flag.String("ip", "", "Specific server IP")
    secretKey := flag.String("key", "", "Secret key for authentication")
    socks5Addr := flag.String("s5", "", "SOCKS5 proxy address")
    fallbackAddr := flag.String("fallback", "", "Fallback address")
    listenAddr := flag.String("listen", "127.0.0.1:10808", "Local listen address")

	flag.Parse()

    // 动态生成 JSON 配置
	configJSON := core.GenerateConfigJSON(*serverAddr, *serverIP, *secretKey, *socks5Addr, *fallbackAddr, *listenAddr)

	log.Println("[CLI] Starting X-Link Ghost Core Engine...")
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
