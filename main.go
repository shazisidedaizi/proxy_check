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

	client := &http.Client{Timeout: 25 * time.Second}
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

func normalizeSocks5Addr(node string) string {
    node = strings.TrimSpace(node)

    if strings.HasPrefix(node, "socks5://") {
        node = strings.TrimPrefix(node, "socks5://")
    }
    if strings.HasPrefix(node, "socks://") {
        node = strings.TrimPrefix(node, "socks://")
    }

    // 去掉 user:pass@
    if strings.Contains(node, "@") {
        parts := strings.Split(node, "@")
        return parts[len(parts)-1] // 最后部分是 host:port
    }

    return node // 已经是 host:port
}

// ====================== 是否为 SOCKS5 蜜罐检测 ======================
func checkSocks5Honeypot(rawNode string) (bool, string) {
    // 节点解析成 ip:port
    addr := normalizeSocks5Addr(rawNode)
    if addr == "" {
        return false, "非 SOCKS5"
    }

    // 连接 TCP
    conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
    if err != nil {
        return false, "无法连接节点"
    }
    defer conn.Close()

    start := time.Now()

    // ===================== 发送初次握手 =====================
    // VER=5, NMETHODS=1, METHODS=NO_AUTH (0x00)
    _, err = conn.Write([]byte{0x05, 0x01, 0x00})
    if err != nil {
        return false, "握手发送失败"
    }

    // 读取 METHOD 选择
    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    method := make([]byte, 2)
    _, err = conn.Read(method)
    if err != nil {
        return false, "未返回握手响应"
    }

    // 正常 SOCKS5 节点：method[0]=5
    if method[0] != 0x05 {
        return true, "VER 不是 0x05, 像蜜罐"
    }

    // ================== 如果需要认证（METHOD=2） ==================
    if method[1] == 0x02 {
        // 真实 SOCKS5 节点常见情况，蜜罐通常不会实现 AUTH
        return false, "需要认证的正常 SOCKS5"
    }

    // 如果不是 NO_AUTH (0x00)，并且不是 AUTH，直接跳过
    if method[1] != 0x00 {
        return false, "不支持的认证类型（但不是蜜罐）"
    }

    // ============= 发送 CONNECT 请求，访问不存在的 IP/端口 =============
    // VER=5, CMD=1, RSV=0, ATYP=1 (IPv4)
    // DST.ADDR=240.0.0.1（不存在的 TEST 地址）
    // DST.PORT=65535（无效端口）
    req := []byte{
        0x05, 0x01, 0x00, 0x01,
        240, 0, 0, 1,
        0xFF, 0xFF,
    }

    _, err = conn.Write(req)
    if err != nil {
        return false, "发送假请求失败"
    }

    // 读取回应（一般 10 字节：VER REP RSV ATYP BND.ADDR BND.PORT）
    resp := make([]byte, 10)
    conn.SetReadDeadline(time.Now().Add(3 * time.Second))
    n, _ := conn.Read(resp)

    elapsed := time.Since(start).Milliseconds()

    // ================== 蜜罐判断逻辑 ==================

    // **** 判定 1：响应过快 ****
    if elapsed <= 20 {
        return true, "响应过快(<20ms)，蜜罐特征"
    }

    // **** 判定 2：固定返回成功 REP=00（但地址不存在）****
    if n >= 2 && resp[1] == 0x00 {
        return true, "固定返回 REP=00，蜜罐"
    }

    // **** 判定 3：BND.PORT=0（蜜罐常见特征）****
    if n >= 10 {
        port := binary.BigEndian.Uint16(resp[8:10])
        if port == 0 {
            return true, "返回 BND.PORT=0，不真实，蜜罐"
        }
    }

    // **** 判定 4：空返回或奇怪包结构 ****
    if n == 0 {
        return true, "空响应，蜜罐概率高"
    }

    // 非蜜罐
    return false, "正常 SOCKS5"
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
    			var isDefinitelyHoney bool = false
    			var honeyReason string
   	 			var successCount int = 0  // 成功建立 SOCKS5 连接的次数

    			for attempt := 0; attempt < 4; attempt++ {  // 最多试 4 次
        			isHoney, reason := checkSocks5Honeypot(addr)
					
					fmt.Printf("[尝试 %d/%d] %s -> %s (isHoney=%v)\n", 
        				attempt+1, 4, node, reason, isHoney)

        			// 1. 连接类错误 → 直接重试，不计入任何判断
        			if strings.Contains(reason, "无法连接") ||
           				strings.Contains(reason, "握手发送失败") ||
           				strings.Contains(reason, "未返回握手响应") ||
           				strings.Contains(reason, "ReadDeadline") {
            			if attempt < 3 {
                			time.Sleep(time.Duration(2<<attempt) * time.Second) // 2s → 4s → 8s
            			}
            			continue
        			}

        			// 2. 只要有一次明确检测到蜜罐特征 → 立刻判定为蜜罐，彻底枪毙
        			if isHoney {
            			isDefinitelyHoney = true
            			honeyReason = reason
            			break
        			}

        			// 3. 这次是正常行为
        			successCount++
			        // 不需要连续，只要总成功次数 >=2 次就认为稳定（足够宽容）
        			if successCount >= 2 {
            			break
        			}

        			time.Sleep(1 * time.Second)
    			}

    			// 最终判断
    			if isDefinitelyHoney {
        			fmt.Printf("[蜜罐] %s -> %s\n", node, honeyReason)
        			return
    			}

    			if successCount == 0 {
        		// 4 次都彻底连不上或超时 → 放弃（不是蜜罐，但也没用）
        			fmt.Printf("[失效] %s -> 多次尝试均无法连接，放弃\n", node)
        			return
    			}

    			// successCount >= 1 并且没有触发蜜罐 → 放行（最宽容但最安全）
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
