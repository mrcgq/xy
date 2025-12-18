// core/config_generator.go
// 辅助生成内核所需的 JSON 配置字符串

package core

import "fmt"

// GenerateConfigJSON 生成供 StartInstance 使用的配置 JSON
// 将 secretKey 和 fallbackIP 组合放入 "token" 字段 (格式: key|fallback)
// 适配 core-binary.go 中的解析逻辑: strings.SplitN(settings.Token, "|", 2)
func GenerateConfigJSON(server, ip, key, s5, fallback, listen string) string {
	var proxySettingsPart string
	if s5 != "" {
		proxySettingsPart = fmt.Sprintf(`,
      "proxy_settings": {
        "socks5_address": "%s"
      }`, s5)
	}

	// 核心传参 Hack: 
	// 将 key 和 fallback 拼接到 token 字段，
	// 让 core-binary.go 在 connectGhostTunnel 中解析拆分。
	specialToken := fmt.Sprintf("%s|%s", key, fallback)

	return fmt.Sprintf(`{
  "inbounds": [
    {
      "tag": "inbound-0",
      "listen": "%s",
      "protocol": "socks"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "ech-proxy",
      "settings": {
        "server": "%s",
        "server_ip": "%s",
        "token": "%s"%s
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "rules": [],
    "defaultOutbound": "proxy"
  }
}`, listen, server, ip, specialToken, proxySettingsPart)
}
