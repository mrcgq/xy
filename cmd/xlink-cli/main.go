package main

import (
	"flag"
	"log"
	"os"

	"github.com/mrcgq/xy/core"
)

func main() {
	// 统一解析命令行参数
	configPath := flag.String("c", "", "Path to config file (JSON)")
	ping := flag.Bool("ping", false, "Enable ping mode")
    // 保留旧的 flag 以便 ping 模式能获取参数
	server := flag.String("server", "", "Server address for ping mode")
	key := flag.String("key", "", "Secret key for ping mode")
	ip := flag.String("ip", "", "Global IP for ping mode")
	
	flag.Parse()

	// ★★★ 核心逻辑：根据 -ping 参数决定行为 ★★★
	if *ping {
		log.Println("Starting Ping Test Mode...")
		// 确保 ping 模式有 server 和 key
		if *server == "" || *key == "" {
			log.Fatalf("Error: --server and --key are required for ping mode.")
		}
		core.RunSpeedTest(*server, *key, *ip)
		return // 测速完成后直接退出
	}

	// --- 默认的代理模式 ---
	var configBytes []byte
	var err error

	if *configPath != "" {
		configBytes, err = os.ReadFile(*configPath)
		if err != nil {
			log.Fatalf("Failed to read config file '%s': %v", *configPath, err)
		}
	} else {
		log.Fatalf("Error: Config file path is required. Use -c <path_to_config.json>")
	}

	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("Failed to start instance: %v", err)
	}
	defer listener.Close()

	log.Println("Xlink Kernel is running. Press Ctrl+C to exit.")
	select {}
}
