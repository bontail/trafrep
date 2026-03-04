package svg

import (
	"fmt"
	"io"
	"math"
	"time"

	"trafRep/internal/stream"
)

// CompareInput содержит данные для визуализации двух pcap-файлов по стримам.
type CompareInput struct {
	Left               [][]stream.TimelineMessage // [stream_idx][msg_idx]
	Right              [][]stream.TimelineMessage
	LeftName           string
	RightName          string
	DeltaShowThreshMs  float64
	DeltaColorThreshMs float64
}

const (
	margin       = 20
	subColWidth  = 140 // ширина одной субколонки (client или server)
	subColGap    = 4   // зазор между client и server внутри стрима
	streamPad    = 12  // зазор между стримами внутри половины
	halfDivider  = 6   // зазор-разделитель между двумя половинами
	msgHeight    = 22
	msgGap       = 3
	headerHeight = 70 // область заголовков сверху

	fontSizeName   = 14
	fontSizeSub    = 11
	fontSizeMsg    = 10
	fontSizeStream = 11
)

// streamColWidth — ширина одного стрима (client + gap + server).
func streamColWidth() int {
	return 2*subColWidth + subColGap
}

// halfWidth — ширина одной половины для n стримов.
func halfWidth(n int) int {
	if n <= 0 {
		return 0
	}
	return n*streamColWidth() + (n-1)*streamPad
}

// layout хранит вычисленные позиции для рендеринга.
type layout struct {
	totalWidth   int
	totalHeight  int
	leftHalfX    int
	rightHalfX   int
	leftStreams  int
	rightStreams int
}

// computeLayout вычисляет размеры и позиции элементов SVG на основе входных данных.
func computeLayout(input CompareInput) layout {
	ls := len(input.Left)
	rs := len(input.Right)
	lw := halfWidth(ls)
	rw := halfWidth(rs)
	tw := margin + lw + halfDivider + rw + margin

	maxMsgs := 0
	for _, s := range input.Left {
		if len(s) > maxMsgs {
			maxMsgs = len(s)
		}
	}
	for _, s := range input.Right {
		if len(s) > maxMsgs {
			maxMsgs = len(s)
		}
	}
	th := headerHeight + maxMsgs*(msgHeight+msgGap) + 40

	return layout{
		totalWidth:   tw,
		totalHeight:  th,
		leftHalfX:    margin,
		rightHalfX:   margin + lw + halfDivider,
		leftStreams:  ls,
		rightStreams: rs,
	}
}

// streamX возвращает x-координату начала стрима с индексом si внутри половины, начинающейся с halfX.
func streamX(halfX, si int) int {
	return halfX + si*(streamColWidth()+streamPad)
}

// deltaInfo хранит информацию о дельте для правого сообщения.
type deltaInfo struct {
	hasDelta bool
	deltaMs  float64
	isServer bool
}

// RenderCompare генерирует SVG с двумя половинами, каждая разбита по стримам с client/server колонками.
func RenderCompare(w io.Writer, input CompareInput) error {
	if len(input.Left) == 0 && len(input.Right) == 0 {
		return fmt.Errorf("no streams to compare")
	}

	lo := computeLayout(input)
	leftBase := findBaseTime(input.Left)
	rightBase := findBaseTime(input.Right)

	minStreams := lo.leftStreams
	if lo.rightStreams < minStreams {
		minStreams = lo.rightStreams
	}
	deltas := make([][]deltaInfo, lo.rightStreams)
	for si := 0; si < lo.rightStreams; si++ {
		deltas[si] = make([]deltaInfo, len(input.Right[si]))
		if si >= minStreams {
			continue
		}
		leftMsgs := input.Left[si]
		rightMsgs := input.Right[si]
		for mi := 0; mi < len(rightMsgs) && mi < len(leftMsgs); mi++ {
			leftRel := leftMsgs[mi].Timestamp.Sub(leftBase)
			rightRel := rightMsgs[mi].Timestamp.Sub(rightBase)
			delta := rightRel - leftRel
			deltaMs := float64(delta) / float64(time.Millisecond)
			if math.Abs(deltaMs) > input.DeltaShowThreshMs {
				deltas[si][mi] = deltaInfo{hasDelta: true, deltaMs: deltaMs, isServer: rightMsgs[mi].IsServer}
			}
		}
	}

	// SVG header
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">
<style>
  .header { font-family: sans-serif; font-size: %dpx; font-weight: bold; fill: #333; }
  .sub { font-family: sans-serif; font-size: %dpx; fill: #888; }
  .stream-hdr { font-family: sans-serif; font-size: %dpx; font-weight: bold; fill: #555; }
  .msg-text { font-family: monospace; font-size: %dpx; fill: #fff; }
  .client-rect { fill: #3b82f6; rx: 3; ry: 3; }
  .server-rect { fill: #22c55e; rx: 3; ry: 3; }
  .client-delta-rect { fill: #ef4444; rx: 3; ry: 3; }
  .server-delta-rect { fill: #eab308; rx: 3; ry: 3; }
</style>
<rect width="100%%" height="100%%" fill="#fafafa"/>
`,
		lo.totalWidth, lo.totalHeight, lo.totalWidth, lo.totalHeight,
		fontSizeName, fontSizeSub, fontSizeStream, fontSizeMsg,
	)

	// Вертикальный разделитель
	divX := lo.rightHalfX - halfDivider/2
	fmt.Fprintf(w, `<line x1="%d" y1="0" x2="%d" y2="%d" stroke="#ccc" stroke-width="2"/>`+"\n",
		divX, divX, lo.totalHeight)

	// Заголовки файлов
	leftCenter := lo.leftHalfX + halfWidth(lo.leftStreams)/2
	rightCenter := lo.rightHalfX + halfWidth(lo.rightStreams)/2
	fmt.Fprintf(w, `<text x="%d" y="20" text-anchor="middle" class="header">%s</text>`+"\n",
		leftCenter, escapeXML(input.LeftName))
	fmt.Fprintf(w, `<text x="%d" y="20" text-anchor="middle" class="header">%s</text>`+"\n",
		rightCenter, escapeXML(input.RightName))

	// Подписи стримов — левая половина
	for si := 0; si < lo.leftStreams; si++ {
		sx := streamX(lo.leftHalfX, si)
		mid := sx + streamColWidth()/2
		fmt.Fprintf(w, `<text x="%d" y="38" text-anchor="middle" class="stream-hdr">Stream %d</text>`+"\n", mid, si+1)
		fmt.Fprintf(w, `<text x="%d" y="52" text-anchor="middle" class="sub">client</text>`, sx+subColWidth/2)
		fmt.Fprintf(w, `<text x="%d" y="52" text-anchor="middle" class="sub">server</text>`+"\n", sx+subColWidth+subColGap+subColWidth/2)
	}

	// Подписи стримов — правая половина
	for si := 0; si < lo.rightStreams; si++ {
		sx := streamX(lo.rightHalfX, si)
		mid := sx + streamColWidth()/2
		fmt.Fprintf(w, `<text x="%d" y="38" text-anchor="middle" class="stream-hdr">Stream %d</text>`+"\n", mid, si+1)
		fmt.Fprintf(w, `<text x="%d" y="52" text-anchor="middle" class="sub">client</text>`, sx+subColWidth/2)
		fmt.Fprintf(w, `<text x="%d" y="52" text-anchor="middle" class="sub">server</text>`+"\n", sx+subColWidth+subColGap+subColWidth/2)
	}

	// Легенда — левая половина
	writeLegend(w, lo.leftHalfX, false)
	// Легенда — правая половина (с дельта-цветами)
	writeLegend(w, lo.rightHalfX, true)

	// Сообщения левой половины
	for si, msgs := range input.Left {
		sx := streamX(lo.leftHalfX, si)
		clientX := sx
		serverX := sx + subColWidth + subColGap
		for mi, msg := range msgs {
			y := headerHeight + mi*(msgHeight+msgGap)
			renderMsg(w, msg, leftBase, clientX, serverX, y, nil, 0)
		}
	}

	// Сообщения правой половины (с дельтами)
	for si, msgs := range input.Right {
		sx := streamX(lo.rightHalfX, si)
		clientX := sx
		serverX := sx + subColWidth + subColGap
		for mi, msg := range msgs {
			y := headerHeight + mi*(msgHeight+msgGap)
			var di *deltaInfo
			if mi < len(deltas[si]) && deltas[si][mi].hasDelta {
				di = &deltas[si][mi]
			}
			renderMsg(w, msg, rightBase, clientX, serverX, y, di, input.DeltaColorThreshMs)
		}
	}

	fmt.Fprintln(w, `</svg>`)
	return nil
}

// writeLegend рисует легенду с цветовыми метками client/server и опционально delta-цветами.
func writeLegend(w io.Writer, x int, withDelta bool) {
	ly := 58
	fmt.Fprintf(w, `<rect x="%d" y="%d" width="10" height="10" class="client-rect"/>`, x, ly)
	fmt.Fprintf(w, `<text x="%d" y="%d" class="sub">client</text>`, x+14, ly+11)
	fmt.Fprintf(w, `<rect x="%d" y="%d" width="10" height="10" class="server-rect"/>`, x+65, ly)
	fmt.Fprintf(w, `<text x="%d" y="%d" class="sub">server</text>`, x+79, ly+11)
	if withDelta {
		fmt.Fprintf(w, `<rect x="%d" y="%d" width="10" height="10" class="client-delta-rect"/>`, x+135, ly)
		fmt.Fprintf(w, `<text x="%d" y="%d" class="sub">client delta</text>`, x+149, ly+11)
		fmt.Fprintf(w, `<rect x="%d" y="%d" width="10" height="10" class="server-delta-rect"/>`, x+225, ly)
		fmt.Fprintf(w, `<text x="%d" y="%d" class="sub">server delta</text>`, x+239, ly+11)
	}
	fmt.Fprintln(w)
}

// renderMsg рисует одно сообщение (прямоугольник + текст) в соответствующей субколонке.
// При наличии deltaInfo и превышении colorThreshMs меняет цвет прямоугольника.
func renderMsg(w io.Writer, msg stream.TimelineMessage, baseTime time.Time, clientX, serverX, y int, di *deltaInfo, colorThreshMs float64) {
	x := clientX
	rectClass := "client-rect"
	if msg.IsServer {
		x = serverX
		rectClass = "server-rect"
	}

	// Если дельта > порога — меняем цвет
	if di != nil && math.Abs(di.deltaMs) > colorThreshMs {
		if msg.IsServer {
			rectClass = "server-delta-rect"
		} else {
			rectClass = "client-delta-rect"
		}
	}

	relDur := msg.Timestamp.Sub(baseTime)
	tsStr := formatRelativeTime(relDur)
	label := truncate(msg.TypeName, 10)

	deltaStr := ""
	if di != nil {
		deltaStr = fmt.Sprintf("(%s)", formatDelta(di.deltaMs))
	}

	fmt.Fprintf(w, `<rect x="%d" y="%d" width="%d" height="%d" class="%s"/>`,
		x, y, subColWidth, msgHeight, rectClass)
	if deltaStr != "" {
		fmt.Fprintf(w, `<text x="%d" y="%d" class="msg-text">%s(%s) %s</text>`+"\n",
			x+3, y+msgHeight/2+4, tsStr, formatDelta(di.deltaMs), escapeXML(label))
	} else {
		fmt.Fprintf(w, `<text x="%d" y="%d" class="msg-text">%s %s</text>`+"\n",
			x+3, y+msgHeight/2+4, tsStr, escapeXML(label))
	}
}

// findBaseTime возвращает самую раннюю временну́ю метку среди всех сообщений всех стримов.
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

// formatRelativeTime форматирует длительность в читаемую строку (например "23ms", "2.150", "1m3.200").
func formatRelativeTime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalMs := d.Milliseconds()
	if totalMs < 1000 {
		return fmt.Sprintf("%dms", totalMs)
	}
	sec := totalMs / 1000
	ms := totalMs % 1000
	if sec < 60 {
		return fmt.Sprintf("%d.%03d", sec, ms)
	}
	min := sec / 60
	sec = sec % 60
	return fmt.Sprintf("%dm%d.%03d", min, sec, ms)
}

// formatDelta форматирует дельту в миллисекундах в строку со знаком (например "+2.3ms", "-1.1ms").
func formatDelta(ms float64) string {
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

// truncate обрезает строку до maxLen символов, добавляя "…" при необходимости.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

// escapeXML экранирует спецсимволы XML (&, <, >, ", ') в строке.
func escapeXML(s string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			result = append(result, []byte("&amp;")...)
		case '<':
			result = append(result, []byte("&lt;")...)
		case '>':
			result = append(result, []byte("&gt;")...)
		case '"':
			result = append(result, []byte("&quot;")...)
		case '\'':
			result = append(result, []byte("&apos;")...)
		default:
			result = append(result, s[i])
		}
	}
	return string(result)
}
