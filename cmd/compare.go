package cmd

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"

	pcappkg "trafRep/internal/pcap"
	"trafRep/internal/stream"
	svgpkg "trafRep/internal/svg"
)

var (
	comparePcap1        string
	comparePcap2        string
	compareHost         string
	comparePort         uint16
	compareOutput       string
	compareDeltaShow    string
	compareDeltaColor   string
)

// CompareCmd генерирует SVG с визуализацией двух pcap-таймлайнов.
var CompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Сравнение двух pcap файлов с генерацией SVG визуализации",
	RunE: func(cmd *cobra.Command, args []string) error {
		deltaShowDur, err := time.ParseDuration(compareDeltaShow)
		if err != nil {
			return fmt.Errorf("invalid --delta-show value %q: %w", compareDeltaShow, err)
		}
		deltaColorDur, err := time.ParseDuration(compareDeltaColor)
		if err != nil {
			return fmt.Errorf("invalid --delta-color value %q: %w", compareDeltaColor, err)
		}

		leftStreams, err := extractStreamTimelines(comparePcap1, compareHost, comparePort)
		if err != nil {
			return fmt.Errorf("pcap1: %w", err)
		}
		rightStreams, err := extractStreamTimelines(comparePcap2, compareHost, comparePort)
		if err != nil {
			return fmt.Errorf("pcap2: %w", err)
		}

		f, err := os.Create(compareOutput)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()

		input := svgpkg.CompareInput{
			Left:               leftStreams,
			Right:              rightStreams,
			LeftName:           comparePcap1,
			RightName:          comparePcap2,
			DeltaShowThreshMs:  float64(deltaShowDur) / float64(time.Millisecond),
			DeltaColorThreshMs: float64(deltaColorDur) / float64(time.Millisecond),
		}
		if err := svgpkg.RenderCompare(f, input); err != nil {
			return fmt.Errorf("render svg: %w", err)
		}

		leftTotal := 0
		for _, s := range leftStreams {
			leftTotal += len(s)
		}
		rightTotal := 0
		for _, s := range rightStreams {
			rightTotal += len(s)
		}
		deltaShowMs := float64(deltaShowDur) / float64(time.Millisecond)
		deltaCount := countDeltas(leftStreams, rightStreams, leftBase(leftStreams), leftBase(rightStreams), deltaShowMs)

		log.Printf("SVG written to %s (%d left streams/%d msgs, %d right streams/%d msgs, %d msgs with delta > %s)",
			compareOutput, len(leftStreams), leftTotal, len(rightStreams), rightTotal, deltaCount, compareDeltaShow)
		return nil
	},
}

func init() {
	CompareCmd.Flags().StringVar(&comparePcap1, "pcap1", "", "Путь к первому pcap файлу")
	CompareCmd.Flags().StringVar(&comparePcap2, "pcap2", "", "Путь ко второму pcap файлу")
	CompareCmd.Flags().StringVar(&compareHost, "host", "", "PostgreSQL хост в pcap файле")
	CompareCmd.Flags().Uint16Var(&comparePort, "port", 5432, "PostgreSQL port в pcap файле")
	CompareCmd.Flags().StringVar(&compareOutput, "output", "compare.svg", "Путь к выходному SVG файлу")
	CompareCmd.Flags().StringVar(&compareDeltaShow, "delta-show", "1ms", "Порог показа дельты в скобках (например 1ms, 500us, 1s)")
	CompareCmd.Flags().StringVar(&compareDeltaColor, "delta-color", "10ms", "Порог смены цвета сообщения (например 10ms, 1s)")

	_ = CompareCmd.MarkFlagRequired("pcap1")
	_ = CompareCmd.MarkFlagRequired("pcap2")
}

// extractStreamTimelines открывает pcap файл, собирает стримы и возвращает таймлайны по стримам.
func extractStreamTimelines(pcapPath, host string, port uint16) ([][]stream.TimelineMessage, error) {
	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	var filterIP net.IP
	if host != "" {
		filterIP = net.ParseIP(host)
	}
	packets := pcappkg.ExtractPackets(handle, filterIP, port)
	log.Printf("Extracted %d tcp packets from %s", len(packets), pcapPath)

	sort.Slice(packets, func(i, j int) bool {
		return packets[i].Timestamp.Before(packets[j].Timestamp)
	})

	manager := stream.NewTCPStreamManager()
	for i, pkt := range packets {
		if err := manager.AddPacket(
			pkt.Data, pkt.Timestamp, pkt.IPSource, pkt.IPDest, pkt.PortSource, pkt.PortDest, host, port,
		); err != nil {
			log.Printf("AddPacket error (packet %d, ts %s): %v", i+1, pkt.Timestamp.Format("15:04:05.000000"), err)
		}
	}

	return manager.GetStreamTimelines(), nil
}

// leftBase возвращает самую раннюю временну́ю метку среди всех сообщений всех стримов.
func leftBase(streams [][]stream.TimelineMessage) time.Time {
	var base time.Time
	for _, s := range streams {
		for _, m := range s {
			if base.IsZero() || m.Timestamp.Before(base) {
				base = m.Timestamp
			}
		}
	}
	return base
}

// countDeltas подсчитывает количество сообщений в правых стримах,
// у которых относительная дельта по модулю превышает threshMs.
func countDeltas(left, right [][]stream.TimelineMessage, leftBaseTime, rightBaseTime time.Time, threshMs float64) int {
	minStreams := len(left)
	if len(right) < minStreams {
		minStreams = len(right)
	}
	count := 0
	for si := 0; si < minStreams; si++ {
		for mi := 0; mi < len(right[si]) && mi < len(left[si]); mi++ {
			leftRel := left[si][mi].Timestamp.Sub(leftBaseTime)
			rightRel := right[si][mi].Timestamp.Sub(rightBaseTime)
			deltaMs := float64(rightRel-leftRel) / float64(time.Millisecond)
			if math.Abs(deltaMs) > threshMs {
				count++
			}
		}
	}
	return count
}
