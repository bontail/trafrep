package cmd

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	pcappkg "trafRep/internal/pcap"
	"trafRep/internal/stream"
)

type FilterSide int

const (
	FilterBoth FilterSide = iota
	FilterClients
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

		filterIP := net.ParseIP(PcapPostgresHost)
		packets := pcappkg.ExtractPackets(handle, filterIP, PcapPostgresPort)
		log.Printf("Extracted %d tcp packets", len(packets))

		sort.Slice(packets, func(i, j int) bool {
			return packets[i].Timestamp.Before(packets[j].Timestamp)
		})

		manager := stream.NewTCPStreamManager()

		for _, pkt := range packets {
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

			flowKey := fmt.Sprintf("%s:%d->%s:%d", pkt.IPSource, pkt.PortSource, pkt.IPDest, pkt.PortDest)
			manager.AddPacket(flowKey, pkt.Data, pkt.Timestamp, pkt.IPSource, pkt.IPDest, pkt.PortSource, pkt.PortDest, PcapPostgresPort)
		}

		messages := manager.CollectMessages()

		sort.Slice(messages, func(i, j int) bool {
			return messages[i].FirstTCPPacketTimestamp.Before(messages[j].FirstTCPPacketTimestamp)
		})

		for i, m := range messages {
			typ := "<len-only>"
			if m.Type != 0 {
				typ = m.Type.String()
			}
			query := stream.ExtractPrettyQuery(m.Payload)
			if query == "" {
				query = "-"
			}
			fmt.Printf("%3d | %s | %s | %s\n",
				i+1,
				m.FirstTCPPacketTimestamp.Format("2006-01-02 15:04:05.000000"),
				typ,
				query,
			)
			if !m.CommandCompleteTimestamp.IsZero() {
				log.Printf("message %d has CommandComplete at %s", i+1, m.CommandCompleteTimestamp.Format(time.RFC3339Nano))
			}
		}
		return nil
	},
}

func init() {
	PrintCmd.Flags().Var(&printFilterSide, "filter", "Фильтр вывода: clients | server | both")
}
