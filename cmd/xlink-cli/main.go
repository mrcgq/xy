// cmd/xlink-cli/main.go (v18.0 - Genesis Edition)
// [新增] --ping 模式入口，实现一体化测速

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"github.com/mrcgq/xy/core" 
)

func main() {
	// --- 代理模式参数 ---
	serverAddr := flag.String("server", "", "Server address (pool separated by ';')")
	serverIP := flag.String("ip", "", "Global fallback server IP")
	secretKey := flag.String("key", "", "Secret key for authentication")
	socks5Addr := flag.String("s5", "", "SOCKS5 proxy address for worker to use")
	fallbackAddr := flag.String("fallback", "", "Fallback address for worker to use")
	listenAddr := flag.String("listen", "127.0.0.1:10808", "Local listen address")
	strategy := flag.String("strategy", "random", "Load balance strategy: random, rr, hash")
	rules := flag.String("rules", "", "Routing rules string")
	
	// --- [v18] 新增：测速模式参数 ---
	pingMode := flag.Bool("ping", false, "Enable ping mode for all nodes in server pool")
	
	flag.Parse()

	// [v18] 模式判断
	if *pingMode {
		// ----------- 进入测速模式 -----------
		if *serverAddr == "" {
			log.Fatal("[CLI] Error: --ping mode requires a --server argument with nodes to test.")
		}
		log.Println("[CLI] Starting X-Link Genesis Kernel (v18.0) in Ping Mode...")
		
		// 调用核心的测速函数
		core.RunSpeedTest(*serverAddr, *secretKey, *serverIP)
		
		log.Println("[CLI] Ping test finished.")

	} else {
		// ----------- 进入代理模式 (旧逻辑) -----------
		if *serverAddr == "" {
			log.Fatal("[CLI] Error: --server argument is required.")
		}
		
		configJSON := core.GenerateConfigJSON(*serverAddr, *serverIP, *secretKey, *socks5Addr, *fallbackAddr, *listenAddr, *strategy, *rules)
		
		log.Println("[CLI] Starting X-Link Genesis Kernel (v18.0) in Proxy Mode...")

		listener, err := core.StartInstance([]byte(configJSON))
		if err != nil {
			log.Fatalf("[CLI] Failed to start core engine: %v", err)
		}
		
		log.Printf("[CLI] Engine running successfully on %s", *listenAddr)

		// 优雅退出
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("[CLI] Shutting down...")
		if listener != nil {
			listener.Close()
		}
	}
}
