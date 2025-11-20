package replay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"trafRep/internal/stream"
)

type Config struct {
	TargetHost string
	TargetPort int
	Rate       float64
	PrintQuery bool
	MaxRetries int
}

// connectTCP устанавливает TCP‑соединение с указанным адресом и возвращает net.Conn.
func connectTCP(targetHost string, targetPort int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	return net.Dial("tcp", addr)
}

// waitForReady читает из conn до тех пор, пока не встретит серверное сообщение типа 'Z' (ReadyForQuery).
// readTimeout задаёт максимальное время ожидания (общий таймаут для поиска 'Z').
// Функция съедает прочитанные байты из соединения (не возвращает их).
func waitForReady(conn net.Conn, readTimeout time.Duration) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}
	deadline := time.Now().Add(readTimeout)
	buf := make([]byte, 0)
	tmp := make([]byte, 4096)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting ReadyForQuery")
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if err == io.EOF {
				return fmt.Errorf("connection closed by remote")
			}
			return fmt.Errorf("read error while waiting ReadyForQuery: %w", err)
		}

		for {
			if len(buf) == 0 {
				break
			}

			first := buf[0]
			isASCIIType := (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')
			if isASCIIType {
				if len(buf) < 5 {
					break
				}
				msgLen := int(binary.BigEndian.Uint32(buf[1:5]))
				if msgLen <= 0 {
					return fmt.Errorf("invalid server length %d", msgLen)
				}
				total := 1 + msgLen
				if len(buf) < total {
					break
				}
				if first == 'Z' {
					return nil
				}
				buf = buf[total:]
				continue
			}

			if len(buf) < 4 {
				break
			}
			msgLen := int(binary.BigEndian.Uint32(buf[0:4]))
			if msgLen <= 0 {
				return fmt.Errorf("invalid server length-only %d", msgLen)
			}
			if len(buf) < msgLen {
				break
			}

			buf = buf[msgLen:]
		}
	}
}

// ReplayMessages сортирует сообщения по времени и воспроизводит их через TCP.
// Временные интервалы между сообщениями масштабируются по config.Rate.
// Если config.Rate == 1.0 — используются оригинальные интервалы (точное время).
// После отправки каждого клиентского сообщения функция ждёт серверное ReadyForQuery ('Z').
func ReplayMessages(messages []stream.PostgreSQLMessage, config Config) error {
	if len(messages) == 0 {
		return fmt.Errorf("no messages to replay")
	}

	sort.Slice(messages, func(i, j int) bool {
		return messages[i].FirstTCPPacketTimestamp.Before(messages[j].FirstTCPPacketTimestamp)
	})

	conn, err := connectTCP(config.TargetHost, config.TargetPort)
	if err != nil {
		log.Printf("failed to connect to target %s:%d: %v", config.TargetHost, config.TargetPort, err)
		conn = nil
	}

	var successCount, errorCount int
	readyTimeout := 40 * time.Second

	firstTime := messages[0].FirstTCPPacketTimestamp
	replayStart := time.Now()

	for i, m := range messages {
		targetOffset := time.Duration(float64(m.FirstTCPPacketTimestamp.Sub(firstTime)) / config.Rate)
		targetTime := replayStart.Add(targetOffset)
		if wait := time.Until(targetTime); wait > 0 {
			//time.Sleep(wait)
		}

		if conn == nil {
			c, err := connectTCP(config.TargetHost, config.TargetPort)
			if err != nil {
				log.Printf("could not connect before sending message %d: %v", i+1, err)
				errorCount++
				continue
			}
			conn = c
		}

		var writeErr error
		for attempt := 0; attempt < config.MaxRetries; attempt++ {
			row := m.Row()
			_, writeErr = conn.Write(row)
			if writeErr == nil {
				break
			}
			log.Printf("Write attempt %d/%d failed for message %d: %v. Reconnecting...", attempt+1, config.MaxRetries, i+1, writeErr)
			_ = conn.Close()
			conn = nil
			time.Sleep(100 * time.Millisecond)
			if attempt < config.MaxRetries-1 {
				c, err := connectTCP(config.TargetHost, config.TargetPort)
				if err == nil {
					conn = c
				}
			}
		}
		if writeErr != nil {
			errorCount++
			log.Printf("Message %d ERROR - write failed: %v", i+1, writeErr)
			continue
		}

		if i != len(messages)-1 {
			if err := waitForReady(conn, readyTimeout); err != nil {
				errorCount++
				log.Printf("Message %d ERROR - waiting ReadyForQuery failed: %v", i+1, err)
				_ = conn.Close()
				conn = nil
				continue
			}
		}

		successCount++
		row := m.Row()
		msg := fmt.Sprintf("Message %d/%d SUCCESS - %d bytes, Type: %s", i+1, len(messages), len(row), m.Type.String())
		if config.PrintQuery && m.Type.IsSimpleQuery() {
			msg += fmt.Sprintf(
				", QUERY: %s", m.PrettyQuery(),
			)
		}
		fmt.Println(msg)
	}

	if conn != nil {
		if err := conn.Close(); err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
			} else {
				log.Printf("Error closing connection: %v", err)
			}
		}
	}

	total := time.Since(replayStart)
	fmt.Fprintf(os.Stdout, "Replay completed: %d messages, %d successful, %d errors, total time: %v\n",
		len(messages), successCount, errorCount, total)
	if errorCount > 0 {
		return fmt.Errorf("replay completed with %d errors", errorCount)
	}
	return nil
}
