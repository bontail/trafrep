package replay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
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

// waitServerMessage читает данные из conn до тех пор, пока не будут получены требуемые серверные ответы.
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
			return fmt.Errorf("timeout waiting server message after client message (%v)", needAnswers)
		}

		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return fmt.Errorf("timeout waiting server message after client message (%v)", needAnswers)
			}
			if err == io.EOF {
				return fmt.Errorf("connection closed by remote (%v)", needAnswers)
			}
			return fmt.Errorf("read error while waiting server message: %w", err)
		}

		for {
			if len(buf) < 4 && !clientMsgType.IsCipherType() ||
				len(buf) != 1 && clientMsgType.IsCipherType() {
				break
			}

			msgType := serverMessageType(buf[0], clientMsgType)
			var processed int
			if msgType.IsNormalType() {
				processed, err = processTypedServerMessage(buf)
				if err != nil {
					return fmt.Errorf("error processing server message: %w", err)
				}
			} else {
				processed = 1 // SSLandGSSENCAnswer
			}
			if needAnswers[msgType] {
				delete(needAnswers, msgType)
			}
			if processed < 1 {
				break
			}
			buf = buf[processed:]
		}
	}
}

func serverMessageType(firstByte byte, clientMsgType message_types.ClientMessageType) message_types.ServerMessageType {
	if clientMsgType.IsCipherType() {
		if message_types.IsSSLandGSSENCAnswer(firstByte) {
			return message_types.SSLandGSSENCAnswer
		}
	}
	return message_types.ServerMessageType(firstByte)
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

// computeInitialWaitTarget возвращает момент времени, в который нужно начинать
// воспроизведение первого сообщения (в составе replayStartTime плюс смещение),
// с учётом небольшой корректировки -100µs.
func computeInitialWaitTarget(replayStartTime time.Time, firstMessage stream.PostgreSQLMessage, startedMessageTime time.Time) time.Time {
	waitTarget := replayStartTime.Add(firstMessage.TimeUntilSendFirstPacket(startedMessageTime))
	return waitTarget.Add(-100 * time.Microsecond)
}

// waitUntil засыпает пока не придёт target (если target в будущем).
func waitUntil(target time.Time) {
	if wait := time.Until(target); wait > 0 {
		time.Sleep(wait)
	}
}

// waitAndConnect ждёт до waitTarget и затем устанавливает TCP‑соединение.
func waitAndConnect(config Config, waitTarget time.Time) (net.Conn, error) {
	waitUntil(waitTarget)
	return connectTCP(config.TargetHost, config.TargetPort)
}

// writeMessage выполняет запись байт сообщения в соединение и возвращает ошибку при неудаче.
func writeMessage(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

// sendAndMaybeWait отправляет сообщение m, при необходимости ждёт серверный ответ,
// логирует результат и возвращает ошибку при неудаче.
func sendAndMaybeWait(conn net.Conn, m stream.PostgreSQLMessage, config Config, streamNumber int, index int, total int) error {
	if err := writeMessage(conn, m.Row()); err != nil {
		return fmt.Errorf("(%d) message %d ERROR - write failed: %v", streamNumber, index, err)
	}

	if err := waitServerMessage(conn, config.ReadTimeout, m.Type); err != nil {
		_ = conn.Close()
		return fmt.Errorf("(%d) message %d/%d (%s) ERROR - waiting server message failed: %v", streamNumber, index, total, m.PrettyQuery(), err)
	}

	msg := fmt.Sprintf("(%d) Message %d/%d SUCCESS - %d bytes, Type: %s", streamNumber, index, total, len(m.Row()), m.Type.String())
	if config.PrintQuery && m.Type.IsSimpleQuery() {
		msg += fmt.Sprintf(", QUERY: %s", m.PrettyQuery())
	}
	log.Println(msg)
	return nil
}

// replayLoop выполняет основную отправку сообщений (кроме первого),
// соблюдая таргетированные временные оффсеты с учётом config.Rate.
func replayLoop(conn net.Conn, messages []stream.PostgreSQLMessage, config Config, replayStartTime time.Time, startedMessageTime time.Time, streamNumber int) error {
	total := len(messages)
	for i := 1; i < total; i++ {
		m := messages[i]
		targetOffset := time.Duration(float64(m.TimeUntilSendFirstPacket(startedMessageTime)) / config.Rate)
		targetTime := replayStartTime.Add(targetOffset)
		waitUntil(targetTime)

		if err := sendAndMaybeWait(conn, m, config, streamNumber, i+1, total); err != nil {
			return err
		}
	}
	return nil
}

// ReplayMessages воспроизводит сообщения через TCP.
func ReplayMessages(messages []stream.PostgreSQLMessage, config Config, replayStartTime time.Time,
	startedMessageTime time.Time, streamNumber int) error {
	if len(messages) == 0 {
		return fmt.Errorf("no messages to replay")
	}
	firstMessage := messages[0]

	waitTarget := computeInitialWaitTarget(replayStartTime, firstMessage, startedMessageTime)
	conn, err := waitAndConnect(config, waitTarget)
	if err != nil {
		return fmt.Errorf("(%d) failed to connect to target %s:%d: %v", streamNumber, config.TargetHost, config.TargetPort, err)
	}
	defer conn.Close()

	if err := sendAndMaybeWait(conn, firstMessage, config, streamNumber, 1, len(messages)); err != nil {
		return err
	}

	if err := replayLoop(conn, messages, config, replayStartTime, startedMessageTime, streamNumber); err != nil {
		return err
	}

	totalDuration := time.Since(replayStartTime)
	log.Printf("(%d) Replay completed: %d messages, total time: %v\n", streamNumber,
		len(messages), totalDuration)
	return nil
}
