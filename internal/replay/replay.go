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

// Config содержит параметры воспроизведения: адрес целевого сервера, коэффициент скорости и таймаут ожидания ответов.
type Config struct {
	TargetHost  string
	TargetPort  int
	Rate        float64
	PrintQuery  bool
	ReadTimeout time.Duration
}

// PacketGroup объединяет PostgreSQL-сообщения, отправленные в одном TCP-пакете.
// Все они отправляются одним вызовом Write; ответ ожидается по типу последнего
// сообщения в группе, которое требует серверного ответа.
type PacketGroup struct {
	messages []stream.PostgreSQLMessage
	data     []byte
	waitType message_types.ClientMessageType
}

// GroupByPacket группирует последовательные сообщения, которые начинаются в
// одном TCP-пакете (определяется по совпадению FirstTCPPacketTimestamp).
func GroupByPacket(messages []stream.PostgreSQLMessage) []PacketGroup {
	var groups []PacketGroup
	i := 0
	for i < len(messages) {
		ts := messages[i].FirstTCPPacketTimestamp
		var groupMsgs []stream.PostgreSQLMessage
		var data []byte
		var waitType message_types.ClientMessageType
		for i < len(messages) && messages[i].FirstTCPPacketTimestamp.Equal(ts) {
			data = append(data, messages[i].Row()...)
			if len(messages[i].Type.NeedAnswers()) > 0 {
				waitType = messages[i].Type
			}
			groupMsgs = append(groupMsgs, messages[i])
			i++
		}
		groups = append(groups, PacketGroup{
			messages: groupMsgs,
			data:     data,
			waitType: waitType,
		})
	}
	return groups
}

// connectTCP устанавливает TCP‑соединение с указанным адресом и возвращает net.Conn.
func connectTCP(targetHost string, targetPort int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	return net.Dial("tcp", addr)
}

// waitServerMessage читает данные из conn до тех пор, пока не будет получен требуемый серверный ответ.
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
			if processed < 1 {
				break
			}
			if needAnswers[msgType] {
				return nil
			}
			buf = buf[processed:]
		}
	}
}

// serverMessageType определяет тип серверного сообщения по первому байту.
// Если ожидается SSL/GSSENC-ответ, возвращает SSLandGSSENCAnswer для соответствующих байтов.
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
func processTypedServerMessage(data []byte) (processedData int, err error) {
	if len(data) < 5 {
		return 0, nil
	}
	msgLen := int(binary.BigEndian.Uint32(data[1:5]))
	if msgLen < 4 {
		return 0, fmt.Errorf("invalid typed server message length: %d", msgLen)
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

// sendGroup отправляет все сообщения группы одним Write и ждёт ответа сервера.
func sendGroup(conn net.Conn, group PacketGroup, config Config, streamNumber int, index int, total int) error {
	if _, err := conn.Write(group.data); err != nil {
		return fmt.Errorf("(%d) group %d/%d ERROR - write failed: %v", streamNumber, index, total, err)
	}

	if err := waitServerMessage(conn, config.ReadTimeout, group.waitType); err != nil {
		_ = conn.Close()
		return fmt.Errorf("(%d) group %d/%d ERROR - waiting server message failed: %v", streamNumber, index, total, err)
	}

	if config.PrintQuery {
		msg := fmt.Sprintf("(%d) Group %d/%d SUCCESS", streamNumber, index, total)
		for _, m := range group.messages {
			msg += fmt.Sprintf(" Type: %s,", m.Type)
			if m.Type.IsSimpleQuery() {
				msg += fmt.Sprintf(" QUERY: %s", m.PrettyQuery())
			}
		}
		log.Printf(msg)
	}
	return nil
}

// replayGroupLoop отправляет группы пакетов начиная со второй,
// соблюдая временны́е оффсеты с учётом config.Rate.
func replayGroupLoop(conn net.Conn, groups []PacketGroup, config Config, replayStartTime time.Time, startedMessageTime time.Time, streamNumber int) error {
	total := len(groups)
	for i := 1; i < total; i++ {
		group := groups[i]
		targetOffset := time.Duration(float64(group.messages[0].TimeUntilSendFirstPacket(startedMessageTime)) / config.Rate)
		targetTime := replayStartTime.Add(targetOffset)
		waitUntil(targetTime)

		if err := sendGroup(conn, group, config, streamNumber, i+1, total); err != nil {
			return err
		}
	}
	return nil
}

// ReplayMessages воспроизводит предварительно сгруппированные сообщения через TCP.
// Каждая группа отправляется одним Write; ответ сервера ожидается по типу последнего
// сообщения в группе, требующего ответа.
func ReplayMessages(groups []PacketGroup, config Config, replayStartTime time.Time,
	startedMessageTime time.Time, streamNumber int) error {
	if len(groups) == 0 {
		return fmt.Errorf("no groups to replay")
	}

	waitTarget := computeInitialWaitTarget(replayStartTime, groups[0].messages[0], startedMessageTime)
	conn, err := waitAndConnect(config, waitTarget)
	if err != nil {
		return fmt.Errorf("(%d) failed to connect to target %s:%d: %v", streamNumber, config.TargetHost, config.TargetPort, err)
	}
	defer conn.Close()

	if err := sendGroup(conn, groups[0], config, streamNumber, 1, len(groups)); err != nil {
		return err
	}

	if err := replayGroupLoop(conn, groups, config, replayStartTime, startedMessageTime, streamNumber); err != nil {
		return err
	}

	totalDuration := time.Since(replayStartTime)
	totalMessages := 0
	for _, g := range groups {
		totalMessages += len(g.messages)
	}
	log.Printf("(%d) Replay completed: %d groups (%d messages), total time: %v", streamNumber,
		len(groups), totalMessages, totalDuration)
	return nil
}
