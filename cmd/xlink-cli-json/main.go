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
	configFile := flag.String("c", "config.json", "Path to config file")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("[CLI] Error: Config file path is required. Usage: -c <path>")
	}

	log.Printf("[CLI] Loading configuration from: %s", *configFile)
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[CLI] Failed to read config file: %v", err)
	}

	log.Println("[CLI] Starting X-Link Core Engine v3.0...")
	listener, err := core.StartInstance(configBytes)
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
