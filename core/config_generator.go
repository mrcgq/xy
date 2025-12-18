package core

import "fmt"

func GenerateConfigJSON(server, ip, key, s5, fallback, listen string) string {
	var proxySettingsPart string
	if s5 != "" {
		proxySettingsPart = fmt.Sprintf(`,
      "proxy_settings": {
        "socks5_address": "%s"
      }`, s5)
	}

	// 注意：这里的 token 字段我们用来传递 密钥(key) 和 fallback地址
	// 这是为了简化参数，内核会解析这个特殊的 "token" 字段
	// 格式: key|fallback
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
