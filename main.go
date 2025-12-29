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
	"regexp"
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
func sendTelegramMessage(botToken, chatId, text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	sendOnce := func() error {
		data := url.Values{}
		data.Set("chat_id", chatId)
		data.Set("text", text)

		resp, err := http.PostForm(apiURL, data)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		return nil
	}

	// 第一次发送
	if err := sendOnce(); err != nil {
		// 等待 1 秒再重试
		time.Sleep(1 * time.Second)

		// 第二次发送
		if err2 := sendOnce(); err2 != nil {
			fmt.Println("TG 发送失败:", err2)
		}
	}
}

// ====================== 调用 API 检测 ======================
func checkProxy(proxyStr, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.szsddz.de5.net/check?proxy=%s&token=%s",
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

// -------------------- 通用预处理函数 --------------------
var ipPortProtoRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})[:|](\d+)(?::|\|)?(http|socks5)?`)

func preprocessNode(raw string) (proto string, addr string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	// 去掉协议前缀
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		proto = strings.ToLower(parts[0])
		raw = parts[1]
	}

	// 去掉认证信息 user:pass@
	if strings.Contains(raw, "@") {
		parts := strings.Split(raw, "@")
		raw = parts[len(parts)-1]
	}

	// 尝试从描述文本提取 ip:port 和协议
	m := ipPortProtoRe.FindStringSubmatch(raw)
	if len(m) >= 3 {
		ip := m[1]
		port := m[2]
		if proto == "" && len(m) == 4 && m[3] != "" {
			proto = strings.ToLower(m[3])
		}
		if proto != "http" && proto != "socks5" {
    		return "", "", false
		}		
		return proto, ip + ":" + port, true
	}

	return "", "", false
}

// -------------------- 蜜罐检测函数 --------------------
func checkHoneypot(proto, addr string) (bool, string) {
    if proto == "socks5" {
        // ---------------- SOCKS5 检测 ----------------
        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err != nil {
            return false, "无法连接节点"
        }
        defer conn.Close()

        start := time.Now()

        // 发送 SOCKS5 握手：版本5 + 无认证
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

        // 发送假的 CONNECT 请求到 240.0.0.1:65535（几乎不可能真实存在）
        req := []byte{0x05, 0x01, 0x00, 0x01, 240, 0, 0, 1, 0xFF, 0xFF}
        _, err = conn.Write(req)
        if err != nil {
            return false, "发送假请求失败"
        }

        resp := make([]byte, 10)
        conn.SetReadDeadline(time.Now().Add(3 * time.Second))
        n, err := conn.Read(resp)
        elapsed := time.Since(start).Milliseconds()

        if elapsed <= 20 {
            return true, "响应过快(<20ms)，蜜罐特征"
        }

        if err != nil || n == 0 {
            return true, "无响应或空响应，蜜罐概率高"
        }

        if n < 4 {
            return true, "响应长度太短，疑似蜜罐"
        }

        if resp[1] == 0x00 {
            // 很多蜜罐固定返回成功（REP=00）
            if n >= 10 {
                port := binary.BigEndian.Uint16(resp[8:10])
                if port == 0 {
                    return true, "返回 BND.PORT=0，不真实，蜜罐"
                }
            }
            return true, "固定返回 REP=00，蜜罐特征"
        }

        return false, "正常 SOCKS5 行为"

    } else if proto == "http" {
        // ---------------- HTTP 检测 ----------------
        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err != nil {
            return false, "无法连接节点"
        }
        defer conn.Close()

        start := time.Now()

        // 标准的 CONNECT 请求（目标使用 example.com:443）
        req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        _, err = conn.Write([]byte(req))
        if err != nil {
            return false, "发送请求失败"
        }

        conn.SetReadDeadline(time.Now().Add(3 * time.Second))
        buf := make([]byte, 1024)
        n, err := conn.Read(buf)
        elapsed := time.Since(start).Milliseconds()

        if err != nil || n == 0 {
            return true, "无有效响应，疑似蜜罐"
        }

        respStr := string(buf[:n])

        // 严格解析第一行（状态行）
        lines := strings.SplitN(respStr, "\r\n", 2)
        if len(lines) == 0 || !strings.HasPrefix(lines[0], "HTTP/1.1 ") {
            return true, "非标准 HTTP 响应起始行"
        }

        statusLine := lines[0]
        fields := strings.Fields(statusLine)
        if len(fields) < 3 { // HTTP/1.1 200 OK 至少要有 3 个字段
            return true, "状态行格式错误或不完整"
        }

        statusCode := fields[1]

        // 成功情况：必须是 200 且包含 "Connection established"（忽略大小写）
        if statusCode == "200" {
            lowerStatus := strings.ToLower(statusLine)
            if strings.Contains(lowerStatus, "connection established") ||
                strings.Contains(lowerStatus, "connected") {
                return false, "正常 HTTP CONNECT 200"
            }
            return true, "200 但缺少 Connection established 关键字，疑似伪装蜜罐"
        }

        // 常见代理响应（仍视为存活节点，但不通过蜜罐检测）
        if statusCode == "407" || statusCode == "403" || statusCode == "503" {
            return false, fmt.Sprintf("代理返回 %s（存活但需认证/拒绝）", statusCode)
        }

        // 其他状态码一律视为异常/蜜罐
        return true, fmt.Sprintf("非预期响应状态码: %s", statusCode)
    }

    return false, "未知协议"
}

// -------------------- 节点提取函数 --------------------
var lineRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})[:|](\d+)[:|](http|socks5)`)

func extractNodeWithProtocol(raw string) (string, bool) {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return "", false
    }

    // 已经是标准格式
    if strings.HasPrefix(raw, "http://") ||
        strings.HasPrefix(raw, "https://") ||
        strings.HasPrefix(raw, "socks5://") {
        return raw, true
    }

    m := lineRe.FindStringSubmatch(raw)
    if len(m) == 4 {
        ip := m[1]
        port := m[2]
        proto := m[3]
        return proto + "://" + ip + ":" + port, true
    }

    return "", false
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

	// 存放节点
	var nodes []string
	seen := make(map[string]bool)

	for scanner.Scan() {
    	raw := strings.TrimSpace(scanner.Text())
    	if raw == "" {
        	continue
    	}

    	// 调用提取函数，将描述型文本转换成标准节点
    	node, ok := extractNodeWithProtocol(raw)
    	if !ok {
        	continue
    	}

    	if seen[node] {
        	continue
    	}
    	seen[node] = true
    	nodes = append(nodes, node)
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

        	// ① 预处理（必须第一步）
        	proto, addr, ok := preprocessNode(node)
	        if !ok {
            	return
        	}

        	// ② 蜜罐检测（按协议分流）
        	isHoney, reason := checkHoneypot(proto, addr)
        	if isHoney {
            	fmt.Printf("[蜜罐][%s] %s -> %s\n", proto, addr, reason)
            	return
        	}

        	// ③ API 检测（统一用标准格式）
        	proxyStr := proto + "://" + addr
        	resp, err := checkProxy(proxyStr, apiToken)
			if err != nil {
    			return
			}
			if !resp.Success {
    			return
			}

        	if resp.Company.Type != "isp" && resp.ASN.Type != "isp" {
            	return
        	}
        	if resp.Delay <= 0 || resp.Delay > 1000 {
            	return
        	}

        	line := fmt.Sprintf("%s#%s", resp.Proxy, resp.Location.CountryCode)
        	fmt.Printf("[有效] %s (%.0fms)\n", line, resp.Delay)

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
