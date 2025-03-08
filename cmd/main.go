package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/compose-ssl-chain/pkg/api"
)

func findAvailablePort(startPort int) (int, error) {
	for port := startPort; port < startPort+100; port++ {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			listener.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("在端口范围 %d-%d 内未找到可用端口", startPort, startPort+100)
}

func main() {
	port := flag.Int("port", 8080, "指定服务端口，如果被占用会自动寻找下一个可用端口")
	flag.Parse()

	// 查找可用端口
	availablePort, err := findAvailablePort(*port)
	if err != nil {
		log.Fatalf("查找可用端口失败: %v", err)
	}

	server := api.NewServer()
	fmt.Printf("启动 Web API 服务在端口 %d...\n", availablePort)
	if err := server.Run(fmt.Sprintf(":%d", availablePort)); err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}
} 