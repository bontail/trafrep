package replay

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"trafRep/internal/models"
)

// connectTCP соединяется к targetHost:targetPort и возвращает net.Conn.
func connectTCP(targetHost string, targetPort int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	return net.Dial("tcp", addr)
}

// ReplayMessages сортирует сообщения по времени и воспроизводит их через TCP,
// соблюдая интервалы между сообщениями (c учётом config.Rate).
// Успехи печатаются в stdout, ошибки — в stderr (log).
func ReplayMessages(messages []models.PostgreSQLMessage, config models.ReplayConfig) error {
	if len(messages) == 0 {
		return fmt.Errorf("no messages to replay")
	}

	// сортируем по времени
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp.Before(messages[j].Timestamp)
	})

	firstTime := messages[0].Timestamp
	replayStart := time.Now()

	conn, err := connectTCP(config.TargetHost, config.TargetPort)
	if err != nil {
		log.Printf("failed to connect to target %s:%d: %v", config.TargetHost, config.TargetPort, err)
		// позволим попытки при первой записи
		conn = nil
	}

	const maxRetries = 3
	var successCount, errorCount int

	for i, m := range messages {
		targetOffset := time.Duration(float64(m.Timestamp.Sub(firstTime)) / config.Rate)
		targetTime := replayStart.Add(targetOffset)
		if wait := time.Until(targetTime); wait > 0 {
			time.Sleep(wait)
		}

		// ensure connected
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
		for attempt := 0; attempt < maxRetries; attempt++ {
			_, writeErr = conn.Write(m.Raw)
			if writeErr == nil {
				break
			}
			log.Printf("Write attempt %d/%d failed for message %d: %v. Reconnecting...", attempt+1, maxRetries, i+1, writeErr)
			_ = conn.Close()
			conn = nil
			time.Sleep(100 * time.Millisecond)
		}
		if writeErr != nil {
			errorCount++
			log.Printf("Message %d ERROR - write failed: %v", i+1, writeErr)
			continue
		}
		successCount++
		// успешные события выводим в stdout
		fmt.Fprintf(os.Stdout, "Message %d/%d SUCCESS - %s:%d -> %s:%d - %d bytes\n",
			i+1, len(messages), m.IPSource, m.PortSource, m.IPDest, m.PortDest, len(m.Raw))
	}

	if conn != nil {
		if err := conn.Close(); err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				// ignore
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
