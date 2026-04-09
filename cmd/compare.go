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
		defer func() { _ = f.Close() }()

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
		default:
			return fmt.Errorf("unsupported format: %s", compareFormat)
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
		delta := collectDeltaStats(leftTimelines, rightTimelines, lb, rb, deltaShowMs)

		log.Printf("%s written to %s (%d left streams/%d msgs, %d right streams/%d msgs, %d groups with delta > %s, max delta %s in stream %d)",
			strings.ToUpper(compareFormat), compareOutput,
			len(leftTimelines), leftTotal, len(rightTimelines), rightTotal,
			delta.AboveCount, compareDeltaShow, formatDeltaMs(delta.AboveMaxMs), delta.AboveMaxStream)

		if delta.SkippedMismatchCount > 0 {
			log.Printf("Delta skipped mismatches: %d (different group shape/type/side at same group index)", delta.SkippedMismatchCount)
		}
		if len(delta.TopPositive) > 0 {
			log.Printf("Top %d positive server-group deltas by abs:", len(delta.TopPositive))
			for i, d := range delta.TopPositive {
				log.Printf("  #%d delta=%s stream=%d group=%d msgs=%d (%d-%d)", i+1, formatDeltaMs(d.DeltaMs), d.Stream, d.GroupIndex, d.MsgCount, d.MsgFrom, d.MsgTo)
			}
		}
		if len(delta.TopNegative) > 0 {
			log.Printf("Top %d negative server-group deltas by abs:", len(delta.TopNegative))
			for i, d := range delta.TopNegative {
				log.Printf("  #%d delta=%s stream=%d group=%d msgs=%d (%d-%d)", i+1, formatDeltaMs(d.DeltaMs), d.Stream, d.GroupIndex, d.MsgCount, d.MsgFrom, d.MsgTo)
			}
		}
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

	sort.SliceStable(packets, func(i, j int) bool {
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

type timelineGroup struct {
	GroupIndex int
	MsgFrom    int
	MsgTo      int
	MsgCount   int
	Timestamp  time.Time
	IsServer   bool
	TypeSig    string
	TypePretty string
}

func buildTimelineGroups(streamMsgs []stream.TimelineMessage) []timelineGroup {
	if len(streamMsgs) == 0 {
		return nil
	}
	groups := make([]timelineGroup, 0, len(streamMsgs))
	start := 0
	for i := 1; i <= len(streamMsgs); i++ {
		split := i == len(streamMsgs) ||
			!streamMsgs[i].Timestamp.Equal(streamMsgs[start].Timestamp) ||
			streamMsgs[i].IsServer != streamMsgs[start].IsServer
		if !split {
			continue
		}

		part := streamMsgs[start:i]
		sigParts := make([]string, 0, len(part))
		for _, m := range part {
			sigParts = append(sigParts, m.TypeName)
		}
		typeSig := strings.Join(sigParts, "|")
		typePretty := typeSig
		if len(typePretty) > 120 {
			typePretty = typePretty[:117] + "..."
		}
		groups = append(groups, timelineGroup{
			GroupIndex: len(groups) + 1,
			MsgFrom:    start + 1,
			MsgTo:      i,
			MsgCount:   i - start,
			Timestamp:  streamMsgs[start].Timestamp,
			IsServer:   streamMsgs[start].IsServer,
			TypeSig:    typeSig,
			TypePretty: typePretty,
		})
		start = i
	}
	return groups
}

type deltaEntry struct {
	Stream      int
	GroupIndex  int
	MsgFrom     int
	MsgTo       int
	MsgCount    int
	DeltaMs     float64
	TypeSummary string
	IsServer    bool
}

// deltaStatsSummary агрегирует дельты по всем сопоставленным сообщениям.
type deltaStatsSummary struct {
	MatchedCount   int
	SumDeltaMs     float64
	SumAbsMs       float64
	MaxDeltaMs     float64
	MaxDeltaStream int

	SkippedMismatchCount int

	AboveCount     int
	AboveSumMs     float64
	AboveAbsMs     float64
	AboveMaxMs     float64
	AboveMaxStream int

	TopPositive []deltaEntry
	TopNegative []deltaEntry
}

func pushTopPositive(top []deltaEntry, candidate deltaEntry, limit int) []deltaEntry {
	if candidate.DeltaMs <= 0 {
		return top
	}
	top = append(top, candidate)
	sort.SliceStable(top, func(i, j int) bool {
		return top[i].DeltaMs > top[j].DeltaMs
	})
	if len(top) > limit {
		top = top[:limit]
	}
	return top
}

func pushTopNegative(top []deltaEntry, candidate deltaEntry, limit int) []deltaEntry {
	if candidate.DeltaMs >= 0 {
		return top
	}
	top = append(top, candidate)
	sort.SliceStable(top, func(i, j int) bool {
		return math.Abs(top[i].DeltaMs) > math.Abs(top[j].DeltaMs)
	})
	if len(top) > limit {
		top = top[:limit]
	}
	return top
}

// collectDeltaStats подсчитывает агрегаты дельты для всех сопоставленных сообщений
// и отдельно для сообщений, чей модуль дельты выше порога threshMs.
func collectDeltaStats(left, right [][]stream.TimelineMessage, leftBaseTime, rightBaseTime time.Time, threshMs float64) deltaStatsSummary {
	stats := deltaStatsSummary{}
	minStreams := len(left)
	if len(right) < minStreams {
		minStreams = len(right)
	}

	for si := 0; si < minStreams; si++ {
		leftGroups := buildTimelineGroups(left[si])
		rightGroups := buildTimelineGroups(right[si])
		minGroups := len(leftGroups)
		if len(rightGroups) < minGroups {
			minGroups = len(rightGroups)
		}

		for gi := 0; gi < minGroups; gi++ {
			leftGroup := leftGroups[gi]
			rightGroup := rightGroups[gi]
			if leftGroup.IsServer != rightGroup.IsServer || leftGroup.MsgCount != rightGroup.MsgCount || leftGroup.TypeSig != rightGroup.TypeSig {
				stats.SkippedMismatchCount++
				continue
			}
			leftRel := leftGroup.Timestamp.Sub(leftBaseTime)
			rightRel := rightGroup.Timestamp.Sub(rightBaseTime)
			deltaMs := float64(rightRel-leftRel) / float64(time.Millisecond)
			abs := math.Abs(deltaMs)

			entry := deltaEntry{
				Stream:      si + 1,
				GroupIndex:  leftGroup.GroupIndex,
				MsgFrom:     leftGroup.MsgFrom,
				MsgTo:       leftGroup.MsgTo,
				MsgCount:    leftGroup.MsgCount,
				DeltaMs:     deltaMs,
				TypeSummary: leftGroup.TypePretty,
				IsServer:    leftGroup.IsServer,
			}
			if leftGroup.IsServer {
				stats.TopPositive = pushTopPositive(stats.TopPositive, entry, 5)
				stats.TopNegative = pushTopNegative(stats.TopNegative, entry, 5)
			}

			stats.MatchedCount++
			stats.SumDeltaMs += deltaMs
			stats.SumAbsMs += abs

			if abs > math.Abs(stats.MaxDeltaMs) {
				stats.MaxDeltaMs = deltaMs
				stats.MaxDeltaStream = si + 1
			}

			if abs > threshMs {
				stats.AboveCount++
				stats.AboveSumMs += deltaMs
				stats.AboveAbsMs += abs

				if abs > math.Abs(stats.AboveMaxMs) {
					stats.AboveMaxMs = deltaMs
					stats.AboveMaxStream = si + 1
				}
			}
		}
	}

	return stats
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
