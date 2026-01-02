package main

import (
	"log"
	"os"

	// 正确地导入 core 包
	"github.com/mrcgq/xy/core" 
)

func main() {
	// 从标准输入或文件读取配置 (这是更通用的做法)
	// 这里我们简化一下，假设配置是通过某种方式获取的
	// 比如，客户端会生成一个 config.json 然后通过 -c 参数传递
    // 为了兼容您客户端的逻辑，我们让 main.go 去解析 -c

    // 简单实现一个命令行参数解析
    var configPath string
    if len(os.Args) > 2 && os.Args[1] == "-c" {
        configPath = os.Args[2]
    } else {
        // 如果没有 -c，可以设置一个默认值或报错
        // log.Println("Usage: program -c <path_to_config.json>")
        // return
        // 为了兼容旧的 flag 解析，我们可以保留 flag 逻辑
        // 但最清晰的是只认 -c
    }

    // 读取配置文件
    configBytes, err := os.ReadFile(configPath)
    if err != nil {
        log.Fatalf("Failed to read config file '%s': %v", configPath, err)
    }

	// 调用 core 包的 StartInstance 函数
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("Failed to start instance: %v", err)
	}
	defer listener.Close()

	log.Println("Xlink Kernel is running. Press Ctrl+C to exit.")
	
    // 阻塞主进程，让服务持续运行
	select {}
}
