package cmd

import (
	"fmt"
	"log"
	"net"
	"sort"

	_ "github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"

	pcappkg "trafRep/internal/pcap"
	"trafRep/internal/replay"
	"trafRep/internal/stream"
)

var (
	replayTargetHost string
	replayTargetPort int
	replayRate       float64
	replayPrintQuery bool // новый флаг: печатать запросы при успешной отправке
	replayMaxRetries int  // new flag: max retries for write attempts
)

// ReplayCmd собирает PostgreSQL‑сообщения из pcap и воспроизводит их на target-host:target-port.
var ReplayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Воспроизведение трафика из pcap файла",
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

			if err := manager.AddPacket(
				pkt.Data, pkt.Timestamp, pkt.IPSource, pkt.IPDest, pkt.PortSource, pkt.PortDest, PcapPostgresHost, PcapPostgresPort,
			); err != nil {
				log.Printf("AddPacket error: %v", err)
			}
		}

		messages := manager.CollectMessages()

		sort.Slice(messages, func(i, j int) bool {
			return messages[i].FirstTCPPacketTimestamp.Before(messages[j].FirstTCPPacketTimestamp)
		})

		if len(messages) == 0 {
			log.Printf("no messages extracted, nothing to replay")
			return nil
		}

		cfg := replay.Config{
			TargetHost: replayTargetHost,
			TargetPort: replayTargetPort,
			Rate:       replayRate,
			PrintQuery: replayPrintQuery,
			MaxRetries: replayMaxRetries,
		}

		if err := replay.ReplayMessages(messages, cfg); err != nil {
			return fmt.Errorf("replay failed: %w", err)
		}
		return nil
	},
}

func init() {
	ReplayCmd.Flags().StringVar(&replayTargetHost, "target-host", "127.0.0.1", "Target host для воспроизведения")
	ReplayCmd.Flags().IntVar(&replayTargetPort, "target-port", 5432, "Target port для воспроизведения")
	ReplayCmd.Flags().Float64Var(&replayRate, "rate", 1.0, "Скорость реплея (1.0 = оригинал)")
	ReplayCmd.Flags().BoolVar(&replayPrintQuery, "print-query", false, "Печатать текст запроса при успешной отправке (если доступен)")
	ReplayCmd.Flags().IntVar(&replayMaxRetries, "max-retries", 3, "Максимальное число попыток записи при ошибке")
}
