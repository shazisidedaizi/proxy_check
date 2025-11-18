package honeypot

import (
	"encoding/binary"
	"net"
	"time"
)

type HoneypotCheckResult struct {
	IsHoneypot bool   `json:"honeypot"`
	Reason     string `json:"reason"`
	ResponseMS int64  `json:"latency_ms"`
}

func CheckSocks5Honeypot(addr string) HoneypotCheckResult {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return HoneypotCheckResult{IsHoneypot: false, Reason: "无法连接节点"}
	}
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x00})

	buf := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err != nil {
		return HoneypotCheckResult{IsHoneypot: false, Reason: "未返回握手响应"}
	}

	if buf[0] == 0x05 && buf[1] == 0x00 {
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
			return HoneypotCheckResult{
				IsHoneypot: true,
				Reason:     "响应过快（<20ms）",
				ResponseMS: elapsed,
			}
		}

		if n >= 2 && resp[1] == 0x00 {
			return HoneypotCheckResult{
				IsHoneypot: true,
				Reason:     "固定返回 success REP=00",
				ResponseMS: elapsed,
			}
		}

		if n >= 10 {
			bndPort := binary.BigEndian.Uint16(resp[8:10])
			if bndPort == 0 {
				return HoneypotCheckResult{
					IsHoneypot: true,
					Reason:     "返回 BND.PORT=0（异常）",
					ResponseMS: elapsed,
				}
			}
		}
	}

	return HoneypotCheckResult{
		IsHoneypot: false,
		Reason:     "非标准 SOCKS5 响应",
	}
}
