package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Result struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Valid    bool   `json:"valid"`
	Latency  int    `json:"latency"`
	ExportIP string `json:"export_ip"`
}

func main() {
	token := os.Getenv("WORKER_TOKEN")
	if token == "" {
		fmt.Println("请设置 WORKER_TOKEN 环境变量")
		return
	}

	file, _ := os.Open("proxies.txt")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	client := &http.Client{Timeout: 10 * time.Second}

	validFile, _ := os.Create("proxy_valid.txt")
	defer validFile.Close()
	writer := bufio.NewWriter(validFile)
	defer writer.Flush()

	workerURL := "https://example-worker.yourdomain.workers.dev/check"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		url := fmt.Sprintf("%s?socks5=%s&token=%s", workerURL, line, token)
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("请求失败 %s: %v\n", line, err)
			continue
		}
		var r Result
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			resp.Body.Close()
			fmt.Printf("解析失败 %s: %v\n", line, err)
			continue
		}
		resp.Body.Close()
		if r.Valid {
			writer.WriteString(fmt.Sprintf("%s\n", line))
			fmt.Printf("有效: %s\n", line)
		} else {
			fmt.Printf("无效: %s\n", line)
		}
	}
}
