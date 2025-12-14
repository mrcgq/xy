// cmd/xlink-cli/main.go (Final Version - Ready for Advanced GUI)
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	// 确保这个导入路径与您的项目结构匹配
	"xlink-project/core" 
)

func main() {
	// 命令行参数：-c (config)，默认值为程序目录下的 config.json
	exePath, _ := os.Executable()
	defaultConfigPath := filepath.Join(filepath.Dir(exePath), "config.json")

	configFile := flag.String("c", defaultConfigPath, "Path to the configuration file (e.g., config.json)")
	flag.Parse()

	if *configFile == "" {
		log.Fatalf("Usage: %s -c <path/to/config.json>", os.Args[0])
	}
	log.Printf("[CLI] Loading configuration from: %s", *configFile)

	// 读取配置文件内容
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[CLI] Failed to read config file: %v", err)
	}

	// 直接将配置文件内容传递给核心
	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Println("[CLI] Engine running successfully.")

	// 优雅地关闭进程
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
