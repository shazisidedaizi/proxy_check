package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ====================== API 结果结构 ======================
type CheckResp struct {
	Success bool `json:"success"`
	Proxy   string `json:"proxy"`
	Delay   float64 `json:"elapsed_ms"`
	Company struct {
		Type string `json:"type"`
	} `json:"company"`
	ASN struct {
		Type string `json:"type"`
	} `json:"asn"`
	Location struct {
		CountryCode string `json:"country_code"`
	} `json:"location"`
}

// ====================== TG 发送函数 ======================
func sendTelegramMessage(botToken, chatId, text string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	data := url.Values{}
	data.Set("chat_id", chatId)
	data.Set("text", text)
	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ====================== 调用 API 检测 ======================
func checkProxy(proxyStr, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.xn--xg8h.netlib.re/check?proxy=%s&token=%s",
		url.QueryEscape(proxyStr), apiToken,
	)
	client := &http.Client{Timeout: 25 * time.Second}
	var result CheckResp
	var err error
	maxRetries := 3
	baseDelay := 2 * time.Second
	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, e := client.Get(api)
		if e != nil {
			err = e
			time.Sleep(baseDelay * time.Duration(1<<(attempt-1)))
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		err = json.Unmarshal(bodyBytes, &result)
		if err != nil {
			time.Sleep(baseDelay * time.Duration(1<<(attempt-1)))
			continue
		}
		if result.Success {
			break
		}
	}
	return result, err
}

// ====================== 蜜罐检测函数 ======================
func normalizeSocks5Addr(node string) string {
	node = strings.TrimSpace(node)
	if strings.HasPrefix(node, "socks5://") {
		node = strings.TrimPrefix(node, "socks5://")
	}
	if strings.Contains(node, "@") {
		parts := strings.Split(node, "@")
		return parts[len(parts)-1]
	}
	return node
}

func checkSocks5Honeypot(rawNode string) (bool, string) {
	addr := normalizeSocks5Addr(rawNode)
	if addr == "" {
		return false, "非 SOCKS5"
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, "无法连接节点"
	}
	defer conn.Close()

	start := time.Now()
	// VER=5, NMETHODS=1, NO_AUTH
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return false, "握手发送失败"
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	method := make([]byte, 2)
	_, err = conn.Read(method)
	if err != nil {
		return false, "未返回握手响应"
	}
	if method[0] != 0x05 {
		return true, "VER 不是 0x05，像蜜罐"
	}
	if method[1] == 0x02 {
		return false, "需要认证的正常 SOCKS5"
	}
	if method[1] != 0x00 {
		return false, "不支持的认证类型（非蜜罐）"
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, 240, 0, 0, 1, 0xFF, 0xFF}
	_, err = conn.Write(req)
	if err != nil {
		return false, "发送假请求失败"
	}
	resp := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(resp)
	elapsed := time.Since(start).Milliseconds()

	if elapsed <= 20 {
		return true, "响应过快(<20ms)，蜜罐特征"
	}
	if n >= 2 && resp[1] == 0x00 {
		return true, "固定返回 REP=00，蜜罐"
	}
	if n >= 10 {
		port := binary.BigEndian.Uint16(resp[8:10])
		if port == 0 {
			return true, "返回 BND.PORT=0，不真实，蜜罐"
		}
	}
	if n == 0 {
		return true, "空响应，蜜罐概率高"
	}
	return false, "正常 SOCKS5"
}

// ========================= 主程序 =========================
func main() {
	botToken := os.Getenv("BOT_TOKEN")
	chatId := os.Getenv("CHAT_ID")
	apiToken := os.Getenv("API_TOKEN")
	nodesURL := os.Getenv("NODES_URL") // 支持本地文件路径或 http/https 网址

	if botToken == "" || chatId == "" || apiToken == "" || nodesURL == "" {
		fmt.Println("缺少必要的环境变量：BOT_TOKEN CHAT_ID API_TOKEN NODES_URL")
		os.Exit(1)
	}

	// ==================== 支持 URL 或本地文件 ====================
	var scanner *bufio.Scanner
	if strings.HasPrefix(strings.ToLower(nodesURL), "http://") || strings.HasPrefix(strings.ToLower(nodesURL), "https://") {
		// 远程下载
		resp, err := http.Get(nodesURL)
		if err != nil {
			fmt.Printf("下载节点列表失败: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("下载节点列表失败，状态码: %d\n", resp.StatusCode)
			os.Exit(1)
		}
		scanner = bufio.NewScanner(resp.Body)
	} else {
		// 本地文件（兼容旧方式）
		file, err := os.Open(nodesURL)
		if err != nil {
			fmt.Println("打开节点文件失败:", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	var nodes []string
	seen := make(map[string]bool)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		nodes = append(nodes, raw)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("读取节点列表出错: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("加载完成：共 %d 个唯一节点\n", len(nodes))

	type NodeResult struct {
		Line    string
		Country string
		Delay   float64
	}

	var results []NodeResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrency := 20
	sem := make(chan struct{}, concurrency)

	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(node string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 蜜罐检测
			isHoney, reason := checkSocks5Honeypot(node)
			if isHoney {
				fmt.Printf("[蜜罐] %s -> %s\n", node, reason)
				return
			}

			// API 检测
			resp, err := checkProxy(node, apiToken)
			if err != nil || !resp.Success {
				fmt.Printf("节点无效或请求失败: %s\n", node)
				return
			}
			if resp.Company.Type != "isp" && resp.ASN.Type != "isp" {
				return
			}
			if resp.Delay <= 0 || resp.Delay > 1000 {
				return
			}

			line := fmt.Sprintf("%s#%s", resp.Proxy, resp.Location.CountryCode)
			fmt.Printf("[有效] %s (延迟: %.0fms)\n", line, resp.Delay)

			mu.Lock()
			results = append(results, NodeResult{
				Line:    line,
				Country: resp.Location.CountryCode,
				Delay:   resp.Delay,
			})
			mu.Unlock()
		}(node)
	}
	wg.Wait()

	// 排序：国家 → 延迟
	sort.Slice(results, func(i, j int) bool {
		if results[i].Country == results[j].Country {
			return results[i].Delay < results[j].Delay
		}
		return results[i].Country < results[j].Country
	})

	var good []string
	for _, r := range results {
		good = append(good, r.Line)
	}

	if len(good) == 0 {
		sendTelegramMessage(botToken, chatId, "本次扫描无有效代理节点")
		return
	}

	batchSize := 50
	for i := 0; i < len(good); i += batchSize {
		end := i + batchSize
		if end > len(good) {
			end = len(good)
		}
		text := fmt.Sprintf("可用代理列表（按国家排序 %d-%d）：\n%s", i+1, end, strings.Join(good[i:end], "\n"))
		sendTelegramMessage(botToken, chatId, text)
	}

	fmt.Printf("扫描完成：共 %d 个节点，%d 个有效\n", len(nodes), len(good))
}
