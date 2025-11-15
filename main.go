package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ====================== API 结果结构 ======================
type CheckResp struct {
	Success bool   `json:"success"`
	Proxy   string `json:"proxy"`
	Country string `json:"country_code"` // 正确取 TR, US, JP...
	Delay   int    `json:"elapsed_ms"`   // 延迟（毫秒），建议保留

	Company struct {
		Type string `json:"type"`
	} `json:"company"`

	ASN struct {
		Type string `json:"type"`
	} `json:"asn"`
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

// ====================== 调用 API 检测，带 3 次指数退避 + 完整调试 ======================
func checkProxy(proxyStr, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.xn--xg8h.netlib.re/check?proxy=%s&token=%s",
		url.QueryEscape(proxyStr), apiToken,
	)
	// 调试：打印完整请求 URL
	fmt.Printf("检测节点 → %s\n", api)

	client := &http.Client{Timeout: 15 * time.Second}
	var result CheckResp
	var err error
	maxRetries := 3
	baseDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, e := client.Get(api)
		if e != nil {
			err = e
			fmt.Printf("请求失败 (%d/%d): %v | 节点: %s\n", attempt, maxRetries, e, proxyStr)
		} else {
			defer resp.Body.Close()
			bodyBytes, _ := io.ReadAll(resp.Body)

			// 调试：打印 API 原始返回（最重要！）
			fmt.Printf("API 原始返回 (%d/%d):\n%s\n", attempt, maxRetries, string(bodyBytes))

			// 解析 JSON
			err = json.Unmarshal(bodyBytes, &result)
			if err != nil {
				fmt.Printf("JSON 解析失败 (%d/%d): %v\n", attempt, maxRetries, err)
				continue
			}

			if result.Success {
				break // 成功，退出重试
			} else {
				fmt.Printf("节点无效 (%d/%d): %s\n", attempt, maxRetries, proxyStr)
			}
		}

		// 重试等待
		if attempt < maxRetries {
			wait := baseDelay * (1 << (attempt - 1)) // 2, 4, 8 秒
			fmt.Printf("等待 %v 后重试...\n", wait)
			time.Sleep(wait)
		}
	}
	return result, err
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

	// ====================== 1. 下载节点 + 调试 ======================
	nodes, err := fetchNodesFromURL(nodesURL)
	if err != nil {
		fmt.Println("下载节点列表失败:", err)
		os.Exit(1)
	}

	// 调试：打印节点数量 + 前几条
	fmt.Printf("共下载到 %d 个节点\n", len(nodes))
	if len(nodes) > 0 {
		fmt.Println("前 3 条节点示例:")
		for i := 0; i < 3 && i < len(nodes); i++ {
			fmt.Printf("  [%d] %s\n", i+1, nodes[i])
		}
	} else {
		fmt.Println("警告：节点列表为空！")
	}

	// ====================== 2. 检测节点 ======================
	var good []string
	for _, node := range nodes {
		resp, err := checkProxy(node, apiToken)
		if err != nil || !resp.Success {
			fmt.Printf("节点无效或请求失败: %s\n", node)
			continue
		}

		// 判断是否为 ISP
		if resp.Company.Type != "isp" && resp.ASN.Type != "isp" {
			fmt.Printf("不是 ISP，跳过: %s\n", node)
			continue
		}

		// 格式化：socks5://user:pass@ip:port#TR
		line := fmt.Sprintf("%s#%s", resp.Proxy, resp.Country)
		fmt.Printf("有效节点: %s\n", line)
		good = append(good, line)
	}

	// ====================== 3. 统计 + 发送 ======================
	fmt.Printf("扫描完成：共 %d 个节点，%d 个有效\n", len(nodes), len(good))

	if len(good) == 0 {
		sendTelegramMessage(botToken, chatId, "本次扫描无有效代理节点")
		return
	}

	text := "可用代理列表：\n" + strings.Join(good, "\n")
	sendTelegramMessage(botToken, chatId, text)
}
