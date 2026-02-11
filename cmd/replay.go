package cmd

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	_ "github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"

	pcappkg "trafRep/internal/pcap"
	"trafRep/internal/replay"
	"trafRep/internal/stream"
)

var (
	replayTargetHost         string
	replayTargetPort         int
	replayRate               float64
	replayPrintQuery         bool
	replayReadTimeoutSeconds int
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

		var filterIP net.IP = nil
		if PcapPostgresHost != "" {
			filterIP = net.ParseIP(PcapPostgresHost)
		}
		packets := pcappkg.ExtractPackets(
			handle,
			filterIP,
			PcapPostgresPort,
		)
		log.Printf("Extracted %d tcp packets", len(packets))

		sort.Slice(packets, func(i, j int) bool {
			return packets[i].Timestamp.
				Before(packets[j].Timestamp)
		})

		manager := stream.NewTCPStreamManager()

		for _, pkt := range packets {

			if err := manager.AddPacket(
				pkt.Data,
				pkt.Timestamp,
				pkt.IPSource,
				pkt.IPDest,
				pkt.PortSource,
				pkt.PortDest,
				PcapPostgresHost,
				PcapPostgresPort,
			); err != nil {
				log.Printf("AddPacket error: %v", err)
			}
		}

		streams := manager.GetStreamMessages()

		if len(streams) == 0 {
			log.Printf("no messages extracted, nothing to replay")
			return nil
		}

		cfg := replay.Config{
			TargetHost:  replayTargetHost,
			TargetPort:  replayTargetPort,
			Rate:        replayRate,
			PrintQuery:  replayPrintQuery,
			ReadTimeout: time.Second * time.Duration(replayReadTimeoutSeconds),
		}

		startedMessageTime := streams[0][0].FirstTCPPacketTimestamp
		for _, stream := range streams {
			if stream[0].FirstTCPPacketTimestamp.Before(startedMessageTime) {
				startedMessageTime = stream[0].FirstTCPPacketTimestamp
			}
		}

		replayStart := time.Now()
		var wg sync.WaitGroup
		for i, stream := range streams {
			wg.Go(func() {
				if err := replay.ReplayMessages(stream, cfg, replayStart, startedMessageTime, i); err != nil {
					log.Printf("replay stream error: %v", err)
				}
			})
		}
		wg.Wait()
		return nil
	},
}

func init() {
	ReplayCmd.Flags().StringVar(&replayTargetHost, "target-host", "127.0.0.1", "Target host для воспроизведения")
	ReplayCmd.Flags().IntVar(&replayTargetPort, "target-port", 5432, "Target port для воспроизведения")
	ReplayCmd.Flags().Float64Var(&replayRate, "rate", 1.0, "Скорость реплея (1.0 = оригинал)")
	ReplayCmd.Flags().BoolVar(&replayPrintQuery, "print-query", false, "Печатать текст запроса при успешной отправке (если доступен)")
	ReplayCmd.Flags().IntVar(&replayReadTimeoutSeconds, "ready-timeout", 25, "Таймаут ожидания ответа сервера в секундах")
}
