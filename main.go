package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/google/gopacket/pcap"

	"trafRep/internal/models"
	pcap2 "trafRep/internal/pcap"
	"trafRep/internal/replay"
	"trafRep/internal/stream"
)

// Mode описывает режим работы (print или replay).
type Mode int

const (
	// ModePrint — только печать сообщений.
	ModePrint Mode = iota
	// ModeReplay — воспроизведение сообщений.
	ModeReplay
)

var modeName = map[Mode]string{
	ModePrint:  "print",
	ModeReplay: "replay",
}

var modeValue = map[string]Mode{
	"print":  ModePrint,
	"replay": ModeReplay,
}

func (m Mode) String() string {
	if n, ok := modeName[m]; ok {
		return n
	}
	return fmt.Sprintf("Mode(%d)", int(m))
}

// ParseMode пробует разобрать строку в Mode.
func ParseMode(s string) (Mode, bool) {
	if v, ok := modeValue[s]; ok {
		return v, true
	}
	return 0, false
}

// CLIConfig содержит параметры, переданные в программу через флаги.
type CLIConfig struct {
	PcapFile   string
	FilterHost string
	FilterPort int
	Mode       Mode
	ReplayHost string
	ReplayPort int
}

// parseCLI парсит флаги командной строки и возвращает конфиг.
// Завершает работу программы в случае ошибочного ввода.
func parseCLI() CLIConfig {
	var cfg CLIConfig
	var modeStr string

	flag.StringVar(&cfg.PcapFile, "pcap", "", "pcap filename (required)")
	flag.StringVar(&cfg.FilterHost, "filter-host", "0.0.0.0", "PostgreSQL server host to filter (pcap)")
	flag.IntVar(&cfg.FilterPort, "filter-port", 5432, "PostgreSQL server port to filter (pcap)")
	flag.StringVar(&modeStr, "mode", "print", `mode: "print" to only print detected queries, "replay" to replay`)
	flag.StringVar(&cfg.ReplayHost, "replay-host", "127.0.0.1", "target host for replay mode")
	flag.IntVar(&cfg.ReplayPort, "replay-port", 5432, "target port for replay mode")
	flag.Parse()

	if cfg.PcapFile == "" {
		fmt.Fprintln(os.Stderr, "--pcap is required")
		os.Exit(1)
	}

	m, ok := ParseMode(modeStr)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", modeStr)
		os.Exit(1)
	}
	cfg.Mode = m

	return cfg
}

// buildMessagesFromPcap читает pcap-файл из handle и собирает поток сообщений PostgreSQL,
// используя stream.TCPStreamManager. Возвращает слайс собранных сообщений.
func buildMessagesFromPcap(handle *pcap.Handle, filterHost string, filterPort int) ([]models.PostgreSQLMessage, error) {
	packets := pcap2.ExtractPackets(handle, filterHost, filterPort)
	log.Printf("Extracted %d total TCP packets from pcap", len(packets))

	manager := stream.NewTCPStreamManager()
	var messages []models.PostgreSQLMessage

	// сортируем пакеты по времени, чтобы правильно отслеживать время начала сообщений
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].Timestamp.Before(packets[j].Timestamp)
	})

	for _, pkt := range packets {
		// учитываем только пакеты, направленные к серверу (filterPort)
		if int(pkt.PortDest) == filterPort {
			flowKey := fmt.Sprintf("%s:%d->%s:%d", pkt.IPSource, pkt.PortSource, pkt.IPDest, pkt.PortDest)
			msgs := manager.AddPacket(flowKey, pkt.Data, pkt.Timestamp, pkt.IPSource, pkt.IPDest, pkt.PortSource, pkt.PortDest)
			if len(msgs) > 0 {
				messages = append(messages, msgs...)
			}
		}
	}
	// сортировка сообщений по времени отправки
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp.Before(messages[j].Timestamp)
	})
	return messages, nil
}

// printMessages печатает найденные сообщения в stdout.
func printMessages(messages []models.PostgreSQLMessage) {
	for _, m := range messages {
		firstWord := ""
		if m.Query != "" {
			firstWord = m.Query
		}
		fmt.Printf("%s %s:%d -> %s:%d | %s\n",
			m.Timestamp.Format("2006-01-02 15:04:05.000000"), m.IPSource, m.PortSource, m.IPDest, m.PortDest, firstWord)
	}
}

// runReplay выполняет воспроизведение сообщений через replay.ReplayMessages.
func runReplay(messages []models.PostgreSQLMessage, targetHost string, targetPort int) error {
	config := models.ReplayConfig{
		TargetHost:  targetHost,
		TargetPort:  targetPort,
		Rate:        1.0,
		ExactTiming: true,
	}
	return replay.ReplayMessages(messages, config)
}

// main запускает программу.
func main() {
	cfg := parseCLI()

	handle, err := pcap.OpenOffline(cfg.PcapFile)
	if err != nil {
		log.Fatalf("failed to open pcap: %v", err)
	}
	defer handle.Close()

	messages, err := buildMessagesFromPcap(handle, cfg.FilterHost, cfg.FilterPort)
	if err != nil {
		log.Fatalf("failed to build messages: %v", err)
	}

	switch cfg.Mode {
	case ModePrint:
		printMessages(messages)
	case ModeReplay:
		if err := runReplay(messages, cfg.ReplayHost, cfg.ReplayPort); err != nil {
			log.Fatalf("replay failed: %v", err)
		}
	default:
		// на всякий случай
		log.Fatalf("unsupported mode: %v", cfg.Mode)
	}
}
