package main

import (
    "bufio"
    "encoding/json"
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "sort"
    "strings"
    "time"
)

// ====================== API 结果结构 ======================
type CheckResp struct {
    Success bool   `json:"success"`
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

// ====================== 调用 API 检测，带重试 + 完整调试 ======================
func checkProxy(proxyStr, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.xn--xg8h.netlib.re/check?proxy=%s&token=%s",
		url.QueryEscape(proxyStr), apiToken,
	)
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
			fmt.Printf("API 原始返回 (%d/%d):\n%s\n", attempt, maxRetries, string(bodyBytes))

			err = json.Unmarshal(bodyBytes, &result)
			if err != nil {
				fmt.Printf("JSON 解析失败 (%d/%d): %v\n", attempt, maxRetries, err)
				continue
			}
			if result.Success {
				break
			} else {
				fmt.Printf("节点无效 (%d/%d): %s\n", attempt, maxRetries, proxyStr)
			}
		}

		if attempt < maxRetries {
			wait := baseDelay * (1 << (attempt - 1))
			fmt.Printf("等待 %v 后重试...\n", wait)
			time.Sleep(wait)
		}
	}
	return result, err
}

// ====================== SOCKS5 蜜罐检测 ======================
func checkSocks5Honeypot(proxyAddr string) (isHoneypot bool, reason string) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return false, "无法连接节点"
	}
	defer conn.Close()

	// 发起 SOCKS5 hello
	conn.Write([]byte{0x05, 0x01, 0x00})

	buf := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err != nil {
		return false, "未返回握手响应"
	}

	if buf[0] == 0x05 && buf[1] == 0x00 {
		// 发起假请求
		req := []byte{
			0x05, 0x01, 0x00, 0x01,
			240, 0, 0, 1,
			0xFF, 0xFF,
		}
		conn.Write(req)

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

	// ====================== 1. 下载 + 自动提取 + 去重 ======================
	nodes, err := fetchNodesFromURL(nodesURL)
	if err != nil {
		fmt.Println("下载节点列表失败:", err)
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
			parts := strings.Split(raw, "#")
			proxy = parts[0]
			fmt.Printf("提取代理 ← %s (原: %s)\n", proxy, raw)
		} else if strings.HasPrefix(raw, "socks5://") || strings.HasPrefix(raw, "http://") {
			proxy = raw
			fmt.Printf("标准代理 ← %s\n", proxy)
		} else {
			fmt.Printf("跳过非法: %s\n", raw)
			continue
		}

		if !seen[proxy] {
			seen[proxy] = true
			cleanNodes = append(cleanNodes, proxy)
		} else {
			fmt.Printf("重复跳过: %s\n", proxy)
		}
	}

	nodes = cleanNodes
	fmt.Printf("处理完成：共提取 %d 个唯一代理节点\n", len(nodes))

	if len(nodes) == 0 {
		sendTelegramMessage(botToken, chatId, "本次扫描无有效代理节点")
		return
	}

	// 打印前3个
	fmt.Println("前 3 条有效节点:")
	for i := 0; i < 3 && i < len(nodes); i++ {
		fmt.Printf("  [%d] %s\n", i+1, nodes[i])
	}

	// ====================== 2. 检测节点 ======================
	type NodeResult struct {
		Line    string
		Country string
		Delay   float64
	}

	var results []NodeResult

	for _, node := range nodes {
		// ==================== 新增：蜜罐检测 ====================
		isHoney, honeyReason := checkSocks5Honeypot(strings.TrimPrefix(node, "socks5://"))
		if isHoney {
			fmt.Printf("[蜜罐] %s -> %s\n", node, honeyReason)
			continue // 发现蜜罐，跳过原有 API 检测
		}
		resp, err := checkProxy(node, apiToken)
		if err != nil || !resp.Success {
			fmt.Printf("节点无效或请求失败: %s\n", node)
			continue
		}

		// ISP 判断
		if resp.Company.Type != "isp" && resp.ASN.Type != "isp" {
			fmt.Printf("不是 ISP，跳过: %s\n", node)
			continue
		}

		// 延迟过滤（< 1000ms）
		if resp.Delay > 1000 {
			fmt.Printf("延迟过高 %.0fms，跳过: %s\n", resp.Delay, node)
			continue
		}

		line := fmt.Sprintf("%s#%s", resp.Proxy, resp.Location.CountryCode)
		fmt.Printf("有效节点: %s (延迟: %.0fms)\n", line, resp.Delay)

		results = append(results, NodeResult{
			Line:    line,
			Country: resp.Location.CountryCode,
			Delay:   resp.Delay,
		})
	}

	// ====================== 3. 按国家排序 ======================
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

	// ====================== 4. 统计 + 发送 ======================
	fmt.Printf("扫描完成：共 %d 个节点，%d 个有效（延迟<1000ms，ISP）\n", len(nodes), len(good))

	if len(good) == 0 {
		sendTelegramMessage(botToken, chatId, "本次扫描无有效代理节点")
		return
	}

	text := "可用代理列表（按国家排序）：\n" + strings.Join(good, "\n")
	sendTelegramMessage(botToken, chatId, text)
}
