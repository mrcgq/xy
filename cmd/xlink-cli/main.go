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
	// 【核心修正】改为接收 -c 参数，指向配置文件路径
	configFile := flag.String("c", "config.json", "Path to config file")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("[CLI] Error: Config file path is required. Usage: -c <path>")
	}

	// 1. 读取 C 客户端生成的 config.json 文件
	log.Printf("[CLI] Loading configuration from: %s", *configFile)
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[CLI] Failed to read config file: %v", err)
	}

	// 2. 启动核心引擎
	// core.StartInstance 会解析 JSON 并启动监听
	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Println("[CLI] Engine running successfully.")

	// 3. 阻塞等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
