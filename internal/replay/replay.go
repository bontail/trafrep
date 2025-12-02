package replay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"time"

	"trafRep/internal/stream"
	"trafRep/internal/stream/message_types"
)

type Config struct {
	TargetHost  string
	TargetPort  int
	Rate        float64
	PrintQuery  bool
	ReadTimeout time.Duration
}

// connectTCP устанавливает TCP‑соединение с указанным адресом и возвращает net.Conn.
func connectTCP(targetHost string, targetPort int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	return net.Dial("tcp", addr)
}

// waitServerMessage читает данные из conn до тех пор, пока не будут получены
// требуемые серверные ответы.
// readTimeout задаёт общий таймаут ожидания.
func waitServerMessage(conn net.Conn, readTimeout time.Duration, clientMsgType message_types.ClientMessageType) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}

	needAnswers := maps.Clone(clientMsgType.NeedAnswers())
	if len(needAnswers) < 1 {
		return nil
	}

	deadline := time.Now().Add(readTimeout)
	buf := make([]byte, 0)
	tmp := make([]byte, 4096)

	for {
		if len(needAnswers) < 1 {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting server message after client message")
		}

		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return fmt.Errorf("timeout waiting server message after client message")
			}
			if err == io.EOF {
				return fmt.Errorf("connection closed by remote")
			}
			return fmt.Errorf("read error while waiting server message: %w", err)
		}

		for {
			if len(buf) < 4 {
				break
			}

			msgType := message_types.ServerMessageType(buf[0])
			var processed int
			if msgType.IsNormalType() {
				processed, err = processTypedServerMessage(buf)
				if err != nil {
					return fmt.Errorf("error processing server message: %w", err)
				}
				if needAnswers[msgType] {
					delete(needAnswers, msgType)
				}
			} else {
				processed, err = processUntypedServerMessage(buf)
			}
			if processed < 1 {
				break
			}
			buf = buf[processed:]
		}
	}
}

// processTypedServerMessage парсит серверное сообщение с ведущим байтом типа и
// возвращает количество байт полного сообщения (1 + len) или 0 если данных недостаточно.
// Проверяет корректность длины.
func processTypedServerMessage(data []byte) (processedData int, err error) {
	if len(data) < 5 {
		return 0, nil
	}
	msgLen := int(binary.BigEndian.Uint32(data[1:5]))
	if msgLen <= 0 {
		return 0, fmt.Errorf("invalid typed server message length")
	}

	if len(data) < 1+msgLen {
		return 0, nil
	}
	return 1 + msgLen, nil
}

// processUntypedServerMessage парсит серверное сообщение без ведущего байта типа
// (только длина в первых 4 байтах) и возвращает размер полного сообщения или 0,
// если данных недостаточно.
func processUntypedServerMessage(data []byte) (processedData int, err error) {
	msgLen := int(binary.BigEndian.Uint32(data[0:4]))
	if msgLen <= 0 {
		return 0, fmt.Errorf("invalid length-only server message length")
	}
	if len(data) < msgLen {
		return 0, nil
	}
	return msgLen, nil
}

// ReplayMessages сортирует сообщения по времени и воспроизводит их через TCP.
// После отправки некоторых клиентских сообщений функция ждёт серверное ReadyForQuery.
func ReplayMessages(messages []stream.PostgreSQLMessage, config Config, replayStartTime time.Time, startedMessageTime time.Time) error {
	if len(messages) == 0 {
		return fmt.Errorf("no messages to replay")
	}
	firstMessage := messages[0]

	waitTarget := replayStartTime.Add(
		firstMessage.FirstTCPPacketTimestamp.Sub(startedMessageTime),
	)
	waitTarget = waitTarget.Add(-100 * time.Microsecond) // небольшая задержка из-за учета установки соединения
	if wait := time.Until(waitTarget); wait > 0 {
		time.Sleep(wait)
	}

	conn, err := connectTCP(config.TargetHost, config.TargetPort)
	if err != nil {
		return fmt.Errorf("failed to connect to target %s:%d: %v", config.TargetHost, config.TargetPort, err)
	}
	defer conn.Close()

	_, writeErr := conn.Write(firstMessage.Row())
	if writeErr != nil {
		return fmt.Errorf("message %d ERROR - write failed: %v", 1, writeErr)
	}
	if err = waitServerMessage(conn, config.ReadTimeout, message_types.StartMessage); err != nil {
		_ = conn.Close()
		return fmt.Errorf("message %d ERROR - waiting server message failed: %v", 1, err)
	}
	fmt.Printf("Message %d/%d SUCCESS - %d bytes, Type: %s\n", 1, len(messages), len(firstMessage.Row()), firstMessage.Type.String())

	for i := 1; i < len(messages)-1; i++ {
		m := messages[i]
		targetOffset := time.Duration(float64(m.FirstTCPPacketTimestamp.Sub(startedMessageTime)) / config.Rate)
		targetTime := replayStartTime.Add(targetOffset)
		if wait := time.Until(targetTime); wait > 0 {
			time.Sleep(wait)
		}

		_, writeErr = conn.Write(m.Row())

		if writeErr != nil {
			return fmt.Errorf("message %d ERROR - write failed: %v", i+1, writeErr)
		}
		if err = waitServerMessage(conn, config.ReadTimeout, m.Type); err != nil {
			_ = conn.Close()
			return fmt.Errorf("message %d ERROR - waiting server message failed: %v", i+1, err)
		}

		msg := fmt.Sprintf("Message %d/%d SUCCESS - %d bytes, Type: %s", i+1, len(messages), len(m.Row()), m.Type.String())
		if config.PrintQuery && m.Type.IsSimpleQuery() {
			msg += fmt.Sprintf(
				", QUERY: %s", m.PrettyQuery(),
			)
		}
		fmt.Println(msg)
	}

	lastMessage := messages[len(messages)-1]
	targetOffset := time.Duration(float64(lastMessage.FirstTCPPacketTimestamp.Sub(startedMessageTime)) / config.Rate)
	targetTime := replayStartTime.Add(targetOffset)
	if wait := time.Until(targetTime); wait > 0 {
		time.Sleep(wait)
	}
	_, writeErr = conn.Write(lastMessage.Row())
	if writeErr != nil {
		return fmt.Errorf("message %d ERROR - write failed: %v", len(messages)-1, writeErr)
	}
	fmt.Printf("Message %d/%d SUCCESS - %d bytes, Type: %s\n", len(messages), len(messages), len(lastMessage.Row()), lastMessage.Type.String())

	total := time.Since(replayStartTime)
	_, err = fmt.Fprintf(os.Stdout, "Replay completed: %d messages, total time: %v\n",
		len(messages), total)
	if err != nil {
		return err
	}
	return nil
}
