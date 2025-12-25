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
	serverAddr := flag.String("server", "", "Server address (single or pool separated by ';')")
	serverIP := flag.String("ip", "", "Specific server IP")
	secretKey := flag.String("key", "", "Secret key")
	socks5Addr := flag.String("s5", "", "SOCKS5 proxy address")
	fallbackAddr := flag.String("fallback", "", "Fallback address")
	listenAddr := flag.String("listen", "127.0.0.1:10808", "Local listen address")
	strategy := flag.String("strategy", "random", "Load balance strategy: random, rr, hash")

	flag.Parse()

	if *serverAddr == "" { log.Fatal("[CLI] Error: --server argument is required.") }

	// 生成配置 (支持 v12.6 所有特性)
	configJSON := core.GenerateConfigJSON(*serverAddr, *serverIP, *secretKey, *socks5Addr, *fallbackAddr, *listenAddr, *strategy)
	
	log.Println("[CLI] Starting X-Link Hydra Kernel (v12.6 Verbose Edition)...")

	listener, err := core.StartInstance([]byte(configJSON))
	if err != nil { log.Fatalf("[CLI] Failed to start core engine: %v", err) }
	
	log.Printf("[CLI] Engine running successfully on %s (Strategy: %s)", *listenAddr, *strategy)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	if listener != nil { listener.Close() }
}
