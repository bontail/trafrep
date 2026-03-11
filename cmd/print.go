package cmd

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	pcappkg "trafRep/internal/pcap"
	"trafRep/internal/stream"
)

// FilterSide задаёт сторону соединения, сообщения которой выводит команда print.
type FilterSide int

const (
	// FilterBoth выводит сообщения обоих направлений.
	FilterBoth FilterSide = iota
	// FilterClients выводит только клиентские сообщения.
	FilterClients
	// FilterServer выводит только серверные сообщения.
	FilterServer
)

var filterSideNames = map[FilterSide]string{
	FilterBoth:    "both",
	FilterClients: "clients",
	FilterServer:  "server",
}

var filterSideValues = map[string]FilterSide{
	"both":    FilterBoth,
	"clients": FilterClients,
	"server":  FilterServer,
}

// String возвращает строковое представление FilterSide (реализует fmt.Stringer).
func (fs FilterSide) String() string {
	if s, ok := filterSideNames[fs]; ok {
		return s
	}
	return "unknown"
}

// Set парсит строковое значение флага и устанавливает соответствующий FilterSide.
// В случае некорректного значения возвращает ошибку с перечнем допустимых вариантов.
func (fs *FilterSide) Set(s string) error {
	if s == "" {
		*fs = FilterBoth
		return nil
	}
	low := strings.ToLower(s)
	if v, ok := filterSideValues[low]; ok {
		*fs = v
		return nil
	}

	keys := make([]string, 0, len(filterSideValues))
	for k := range filterSideValues {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Errorf("invalid filter value: %q (allowed: %s)", s, strings.Join(keys, "|"))
}

// Type возвращает имя типа флага для cobra/pflag (реализует pflag.Value).
func (fs FilterSide) Type() string {
	return "filterSide"
}

var printFilterSide = FilterBoth

// PrintCmd читает pcap, собирает клиентские PostgreSQL‑сообщения (с учётом флага --filter)
// и печатает их в stdout. Команда использует GetPcapHandle и пакет internal/pcap для извлечения пакетов.
var PrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Печать информации из pcap файла",
	RunE: func(cmd *cobra.Command, args []string) error {
		handle, err := GetPcapHandle()
		if err != nil {
			return fmt.Errorf("GetPcapHandle error: %w", err)
		}
		defer handle.Close()

		var filterIP net.IP = nil
		if PcapPostgresHost != "" {
			filterIP = net.ParseIP(PcapPostgresHost)
		}
		packets := pcappkg.ExtractPackets(handle, filterIP, PcapPostgresPort)
		log.Printf("Extracted %d tcp packets", len(packets))

		sort.SliceStable(packets, func(i, j int) bool {
			return packets[i].Timestamp.Before(packets[j].Timestamp)
		})

		manager := stream.NewTCPStreamManager()

		for i, pkt := range packets {
			switch printFilterSide {
			case FilterBoth:
			case FilterClients:
				if pkt.PortDest != PcapPostgresPort {
					continue
				}
			case FilterServer:
				if pkt.PortSource != PcapPostgresPort {
					continue
				}
			}

			if err := manager.AddPacket(
				pkt.Data, pkt.Timestamp, pkt.IPSource, pkt.IPDest, pkt.PortSource, pkt.PortDest, PcapPostgresHost, PcapPostgresPort,
			); err != nil {
				log.Printf("AddPacket error (packet %d, ts %s): %v", i+1, pkt.Timestamp.Format("15:04:05.000000"), err)
			}
		}

		streams := manager.GetStreamMessages()
		var messages []stream.PostgreSQLMessage
		for _, s := range streams {
			messages = append(messages, s...)
		}

		sort.SliceStable(messages, func(i, j int) bool {
			return messages[i].FirstTCPPacketTimestamp.Before(messages[j].FirstTCPPacketTimestamp)
		})

		for i, m := range messages {
			typ := m.Type.String()
			query := "-"
			if m.Type.IsSimpleQuery() {
				query = m.PrettyQuery()
			}
			fmt.Printf("%3d | %s | %s | %s\n",
				i+1,
				m.FirstTCPPacketTimestamp.Format("2006-01-02 15:04:05.000000"),
				typ,
				query,
			)
		}
		return nil
	},
}

func init() {
	PrintCmd.Flags().Var(&printFilterSide, "filter", "Фильтр вывода: clients | server | both")
	PrintCmd.MarkPersistentFlagRequired("pcap")
}
