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
	Success bool    `json:"success"`
	Proxy   string  `json:"proxy"`
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

// ====================== 下载节点列表 ======================
func fetchNodesFromURL(rawURL string) ([]string, error) {
	resp, err := http.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var nodes []string
	reader := bufio.NewReader(resp.Body)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		trim := strings.TrimSpace(string(line))
		if trim != "" {
			nodes = append(nodes, trim)
		}
	}
	return nodes, nil
}

// ====================== 调用 API 检测 ======================
func checkProxy(proxyStr, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.xn--xg8h.netlib.re/check?proxy=%s&token=%s",
		url.QueryEscape(proxyStr), apiToken,
	)

	client := &http.Client{Timeout: 15 * time.Second}
	var result CheckResp
	var err error
	maxRetries := 3
	baseDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, e := client.Get(api)
		if e != nil {
			err = e
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		err = json.Unmarshal(bodyBytes, &result)
		if err != nil {
			continue
		}
		if result.Success {
			break
		}
		if attempt < maxRetries {
			time.Sleep(baseDelay * (1 << (attempt - 1)))
		}
	}
	return result, err
}

// ====================== SOCKS5 蜜罐检测 ======================
func checkSocks5Honeypot(proxyAddr string) (bool, string) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return false, "无法连接节点"
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false, "握手发送失败"
	}

	buf := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err != nil {
		return false, "未返回握手响应"
	}

	if buf[0] == 0x05 && buf[1] == 0x00 {
		req := []byte{0x05, 0x01, 0x00, 0x01, 240, 0, 0, 1, 0xFF, 0xFF}
		if _, err := conn.Write(req); err != nil {
			return false, "发送假请求失败"
		}

		resp := make([]byte, 10)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(resp)

		elapsed := time.Since(start).Milliseconds()
		if elapsed < 20 {
			return true, "响应过快(<20ms)，可能为蜜罐"
		}
		if n >= 2 && resp[1] == 0x00 {
			return true, "固定返回成功 REP=00"
		}
		if n >= 10 {
			bndPort := binary.BigEndian.Uint16(resp[8:10])
			if bndPort == 0 {
				return true, "返回 BND.PORT=0，不真实"
			}
		}
	}

	return false, "非标准 SOCKS5 或行为正常"
}

// ========================= 主程序 =========================
func main() {
	botToken := os.Getenv("BOT_TOKEN")
	chatId := os.Getenv("CHAT_ID")
	apiToken := os.Getenv("API_TOKEN")
	nodesURL := os.Getenv("NODES_URL")

	if botToken == "" || chatId == "" || apiToken == "" || nodesURL == "" {
		fmt.Println("缺少必要的环境变量，请检查 GitHub Secrets")
		os.Exit(1)
	}

	nodes, err := fetchNodesFromURL(nodesURL)
	if err != nil || len(nodes) == 0 {
		fmt.Println("下载节点列表失败或为空:", err)
		os.Exit(1)
	}

	var cleanNodes []string
	seen := make(map[string]bool)
	for _, raw := range nodes {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var proxy string
		if strings.Contains(raw, "#") {
			proxy = strings.Split(raw, "#")[0]
		} else {
			proxy = raw
		}
		if !seen[proxy] {
			seen[proxy] = true
			cleanNodes = append(cleanNodes, proxy)
		}
	}
	nodes = cleanNodes
	fmt.Printf("处理完成：共 %d 个唯一节点\n", len(nodes))

	// ===================== 并发检测 =====================
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

			addr := node
			if strings.HasPrefix(node, "socks5://") {
				addr = strings.TrimPrefix(node, "socks5://")
			} else if strings.HasPrefix(node, "http://") {
				// HTTP 不检测蜜罐
				addr = ""
			}

			if addr != "" {
				fmt.Println(">>> 准备对以下节点进行蜜罐检测:", node)
				isHoney, honeyReason := checkSocks5Honeypot(addr)
				if isHoney {
					fmt.Printf("[蜜罐] %s -> %s\n", node, honeyReason)
					return
				}
			}

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

	// ====================== 排序 ======================
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

	// ====================== Telegram 分批发送 ======================
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
