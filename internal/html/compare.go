package html

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"trafRep/internal/stream"
)

type jsonMessage struct {
	RelMs    float64 `json:"relMs"`
	TypeName string  `json:"typeName"`
	IsServer bool    `json:"isServer"`
}

type jsonCompareData struct {
	Left               [][]jsonMessage `json:"left"`
	Right              [][]jsonMessage `json:"right"`
	LeftName           string          `json:"leftName"`
	RightName          string          `json:"rightName"`
	DeltaShowThreshMs  float64         `json:"deltaShowThreshMs"`
	DeltaColorThreshMs float64         `json:"deltaColorThreshMs"`
	// DivergeRanges[i] — все диапазоны расхождений стрима i, каждый [start, end] (end==-1 до конца).
	DivergeRanges [][][2]int `json:"divergeRanges"`
}

// CompareInput contains the data needed to render an HTML comparison of two pcap files.
type CompareInput struct {
	Left               [][]stream.TimelineMessage
	Right              [][]stream.TimelineMessage
	LeftName           string
	RightName          string
	DeltaShowThreshMs  float64
	DeltaColorThreshMs float64
	// DivergeRanges[i] — все диапазоны расхождений стрима i, каждый [start, end] (end==-1 до конца).
	DivergeRanges [][][2]int
}

// RenderCompare writes a self-contained HTML document with virtual-scroll comparison.
func RenderCompare(w io.Writer, input CompareInput) error {
	if len(input.Left) == 0 && len(input.Right) == 0 {
		return fmt.Errorf("no streams to compare")
	}

	leftBase := findBaseTime(input.Left)
	rightBase := findBaseTime(input.Right)

	data := jsonCompareData{
		Left:               convertStreams(input.Left, leftBase),
		Right:              convertStreams(input.Right, rightBase),
		LeftName:           input.LeftName,
		RightName:          input.RightName,
		DeltaShowThreshMs:  input.DeltaShowThreshMs,
		DeltaColorThreshMs: input.DeltaColorThreshMs,
		DivergeRanges:      input.DivergeRanges,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	html := strings.Replace(compareTemplate, "/*__DATA__*/null", string(jsonBytes), 1)
	_, err = io.WriteString(w, html)
	return err
}

func convertStreams(streams [][]stream.TimelineMessage, base time.Time) [][]jsonMessage {
	result := make([][]jsonMessage, len(streams))
	for i, s := range streams {
		msgs := make([]jsonMessage, len(s))
		for j, m := range s {
			msgs[j] = jsonMessage{
				RelMs:    float64(m.Timestamp.Sub(base)) / float64(time.Millisecond),
				TypeName: m.TypeName,
				IsServer: m.IsServer,
			}
		}
		result[i] = msgs
	}
	return result
}

func findBaseTime(streams [][]stream.TimelineMessage) time.Time {
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
