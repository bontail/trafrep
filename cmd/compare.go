package cmd

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"

	htmlpkg "trafRep/internal/html"
	pcappkg "trafRep/internal/pcap"
	"trafRep/internal/stream"
	svgpkg "trafRep/internal/svg"
)

var (
	comparePcap1      string
	comparePcap2      string
	compareHost       string
	comparePort       uint16
	compareOutput     string
	compareFormat     string
	compareDeltaShow  string
	compareDeltaColor string
)

// CompareCmd генерирует визуализацию двух pcap-таймлайнов (HTML или SVG).
var CompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Сравнение двух pcap файлов с генерацией HTML/SVG визуализации",
	RunE: func(cmd *cobra.Command, args []string) error {
		if compareFormat != "html" && compareFormat != "svg" {
			return fmt.Errorf("invalid --format value %q: must be html or svg", compareFormat)
		}

		deltaShowDur, err := time.ParseDuration(compareDeltaShow)
		if err != nil {
			return fmt.Errorf("invalid --delta-show value %q: %w", compareDeltaShow, err)
		}
		deltaColorDur, err := time.ParseDuration(compareDeltaColor)
		if err != nil {
			return fmt.Errorf("invalid --delta-color value %q: %w", compareDeltaColor, err)
		}

		leftTimelines, err := extractStreams(comparePcap1, compareHost, comparePort)
		if err != nil {
			return fmt.Errorf("pcap1: %w", err)
		}
		rightTimelines, err := extractStreams(comparePcap2, compareHost, comparePort)
		if err != nil {
			return fmt.Errorf("pcap2: %w", err)
		}

		divergeInfos := stream.FindDivergeInfo(leftTimelines, rightTimelines)
		logDivergeInfo(divergeInfos)

		divergeRanges := make([][][2]int, len(divergeInfos))
		for i, di := range divergeInfos {
			ranges := make([][2]int, len(di.Ranges))
			for j, r := range di.Ranges {
				ranges[j] = [2]int{r.Start, r.End}
			}
			divergeRanges[i] = ranges
		}

		f, err := os.Create(compareOutput)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()

		deltaShowMs := float64(deltaShowDur) / float64(time.Millisecond)
		deltaColorMs := float64(deltaColorDur) / float64(time.Millisecond)

		switch compareFormat {
		case "html":
			input := htmlpkg.CompareInput{
				Left:               leftTimelines,
				Right:              rightTimelines,
				LeftName:           comparePcap1,
				RightName:          comparePcap2,
				DeltaShowThreshMs:  deltaShowMs,
				DeltaColorThreshMs: deltaColorMs,
				DivergeRanges:      divergeRanges,
			}
			if err := htmlpkg.RenderCompare(f, input); err != nil {
				return fmt.Errorf("render html: %w", err)
			}
		case "svg":
			input := svgpkg.CompareInput{
				Left:               leftTimelines,
				Right:              rightTimelines,
				LeftName:           comparePcap1,
				RightName:          comparePcap2,
				DeltaShowThreshMs:  deltaShowMs,
				DeltaColorThreshMs: deltaColorMs,
				DivergeRanges:      divergeRanges,
			}
			if err := svgpkg.RenderCompare(f, input); err != nil {
				return fmt.Errorf("render svg: %w", err)
			}
		}

		leftTotal := 0
		for _, s := range leftTimelines {
			leftTotal += len(s)
		}
		rightTotal := 0
		for _, s := range rightTimelines {
			rightTotal += len(s)
		}
		lb := timelineBase(leftTimelines)
		rb := timelineBase(rightTimelines)
		deltaCount, maxDelta, maxDeltaStream := deltaStats(leftTimelines, rightTimelines, lb, rb, deltaShowMs)

		log.Printf("%s written to %s (%d left streams/%d msgs, %d right streams/%d msgs, %d msgs with delta > %s, max delta %s in stream %d)",
			strings.ToUpper(compareFormat), compareOutput,
			len(leftTimelines), leftTotal, len(rightTimelines), rightTotal,
			deltaCount, compareDeltaShow, formatDeltaMs(maxDelta), maxDeltaStream)
		return nil
	},
}

// logDivergeInfo выводит в лог информацию о всех диапазонах расхождений по каждому стриму.
func logDivergeInfo(infos []stream.DivergeInfo) {
	for _, info := range infos {
		streamNum := info.StreamIndex + 1
		if len(info.Ranges) == 0 {
			log.Printf("Stream %d: identical", streamNum)
			continue
		}
		for ri, r := range info.Ranges {
			rangeNum := ri + 1
			if r.LeftType == "" {
				log.Printf("Stream %d range %d: only present in right pcap, from #%d to end (first msg: %q)",
					streamNum, rangeNum, r.Start+1, r.RightType)
			} else if r.RightType == "" {
				log.Printf("Stream %d range %d: only present in left pcap, from #%d to end (first msg: %q)",
					streamNum, rangeNum, r.Start+1, r.LeftType)
			} else if r.End < 0 {
				log.Printf("Stream %d range %d: diverge from #%d to end — left=%q right=%q",
					streamNum, rangeNum, r.Start+1, r.LeftType, r.RightType)
			} else {
				log.Printf("Stream %d range %d: diverge #%d–#%d (resync at #%d) — left=%q right=%q",
					streamNum, rangeNum, r.Start+1, r.End, r.End+1, r.LeftType, r.RightType)
			}
		}
	}
}

func init() {
	CompareCmd.Flags().StringVar(&comparePcap1, "pcap1", "", "Путь к первому pcap файлу")
	CompareCmd.Flags().StringVar(&comparePcap2, "pcap2", "", "Путь ко второму pcap файлу")
	CompareCmd.Flags().StringVar(&compareHost, "host", "", "PostgreSQL хост в pcap файле")
	CompareCmd.Flags().Uint16Var(&comparePort, "port", 5432, "PostgreSQL port в pcap файле")
	CompareCmd.Flags().StringVar(&compareFormat, "format", "html", "Формат вывода: html или svg")
	CompareCmd.Flags().StringVar(&compareOutput, "output", "compare.html", "Путь к выходному файлу")
	CompareCmd.Flags().StringVar(&compareDeltaShow, "delta-show", "1ms", "Порог показа дельты в скобках (например 1ms, 500us, 1s)")
	CompareCmd.Flags().StringVar(&compareDeltaColor, "delta-color", "10ms", "Порог смены цвета сообщения (например 10ms, 1s)")

	_ = CompareCmd.MarkFlagRequired("pcap1")
	_ = CompareCmd.MarkFlagRequired("pcap2")
}

// extractStreams открывает pcap файл и возвращает таймлайны по стримам.
func extractStreams(pcapPath, host string, port uint16) ([][]stream.TimelineMessage, error) {
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

// timelineBase возвращает самую раннюю временну́ю метку среди всех сообщений всех стримов.
func timelineBase(streams [][]stream.TimelineMessage) time.Time {
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

// deltaStats подсчитывает количество сообщений с дельтой > threshMs
// и возвращает максимальную по модулю дельту в миллисекундах.
func deltaStats(left, right [][]stream.TimelineMessage, leftBaseTime, rightBaseTime time.Time, threshMs float64) (count int, maxDeltaMs float64, maxDeltaStream int) {
	minStreams := len(left)
	if len(right) < minStreams {
		minStreams = len(right)
	}
	for si := 0; si < minStreams; si++ {
		for mi := 0; mi < len(right[si]) && mi < len(left[si]); mi++ {
			leftRel := left[si][mi].Timestamp.Sub(leftBaseTime)
			rightRel := right[si][mi].Timestamp.Sub(rightBaseTime)
			deltaMs := float64(rightRel-leftRel) / float64(time.Millisecond)
			abs := math.Abs(deltaMs)
			if abs > math.Abs(maxDeltaMs) {
				maxDeltaMs = deltaMs
				maxDeltaStream = si + 1
			}
			if abs > threshMs {
				count++
			}
		}
	}
	return
}

// formatDeltaMs форматирует дельту в миллисекундах в читаемую строку со знаком.
func formatDeltaMs(ms float64) string {
	if ms == 0 {
		return "0ms"
	}
	sign := "+"
	if ms < 0 {
		sign = ""
	}
	abs := math.Abs(ms)
	if abs >= 1000 {
		return fmt.Sprintf("%s%.1fs", sign, ms/1000)
	}
	if abs >= 1 {
		return fmt.Sprintf("%s%.1fms", sign, ms)
	}
	return fmt.Sprintf("%s%.0fus", sign, ms*1000)
}
