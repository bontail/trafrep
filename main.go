package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	SimpleQuery  = 'Q'
	ParseRequest = 'P'
)

type PostgreSQLMessage struct {
	Timestamp  time.Time
	Query      string
	Type       byte
	IPSource   string
	IPDest     string
	PortSource uint16
	PortDest   uint16
}

func main() {
	var pcapFilename string
	flag.StringVar(&pcapFilename, "pcap", "", "pcap filename")
	flag.Parse()

	if pcapFilename == "" {
		flag.Usage()
		os.Exit(1)
	}

	handle, err := pcap.OpenOffline(pcapFilename)
	if err != nil {
		log.Fatal("Error opening pcap file:", err)
	}
	defer handle.Close()

	messages := parsePostgreSQLPackets(handle)
	_ = messages
	printMessages(messages)
}

func parsePostgreSQLPackets(handle *pcap.Handle) []PostgreSQLMessage {
	var messages []PostgreSQLMessage
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if message, ok := extractPostgreSQLMessage(packet); ok {
			messages = append(messages, message)
		}
	}

	return messages
}

func extractPostgreSQLMessage(packet gopacket.Packet) (PostgreSQLMessage, bool) {
	var ipSrc, ipDst string
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		switch layer := networkLayer.(type) {
		case *layers.IPv4:
			ipSrc = layer.SrcIP.String()
			ipDst = layer.DstIP.String()
		case *layers.IPv6:
			ipSrc = layer.SrcIP.String()
			ipDst = layer.DstIP.String()
		}
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return PostgreSQLMessage{}, false
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	portSrc := uint16(tcp.SrcPort)
	portDst := uint16(tcp.DstPort)

	if portDst != 5432 && portSrc != 5432 {
		return PostgreSQLMessage{}, false
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return PostgreSQLMessage{}, false
	}

	payload := appLayer.Payload()
	if len(payload) < 5 {
		return PostgreSQLMessage{}, false
	}

	msgType := payload[0]
	msgLength := int(binary.BigEndian.Uint32(payload[1:5])) - 4

	if msgLength <= 0 || len(payload) < 5+msgLength {
		return PostgreSQLMessage{}, false
	}

	msgContent := payload[5 : 5+msgLength]

	var query string
	switch msgType {
	case SimpleQuery:
		query = extractNullTerminatedString(msgContent)
	default:
		return PostgreSQLMessage{}, false
	}

	if query == "" {
		return PostgreSQLMessage{}, false
	}

	return PostgreSQLMessage{
		Timestamp:  packet.Metadata().Timestamp,
		Query:      query,
		Type:       msgType,
		IPSource:   ipSrc,
		IPDest:     ipDst,
		PortSource: portSrc,
		PortDest:   portDst,
	}, true
}

func extractNullTerminatedString(data []byte) string {
	idx := bytesToIndex(data, 0)
	if idx == -1 {
		return ""
	}
	return string(data[:idx])
}

func bytesToIndex(data []byte, target byte) int {
	for i, b := range data {
		if b == target {
			return i
		}
	}
	return -1
}

func printMessages(messages []PostgreSQLMessage) {
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp.Before(messages[j].Timestamp)
	})
	fmt.Printf("Found %d PostgreSQL messages:\n\n", len(messages))
	for _, msg := range messages {
		var msgType string
		switch msg.Type {
		case SimpleQuery:
			msgType = "Simple Query"
		case ParseRequest:
			msgType = "Parse"
		default:
			msgType = string(msg.Type)
		}

		fmt.Printf("Time: %s\n", msg.Timestamp.Format("2006-01-02 15:04:05.000000"))
		fmt.Printf("Type: %s\n", msgType)
		fmt.Printf("Source: %s:%d\n", msg.IPSource, msg.PortSource)
		fmt.Printf("Destination: %s:%d\n", msg.IPDest, msg.PortDest)
		fmt.Printf("Query: %s\n", strings.TrimSpace(msg.Query))
		fmt.Println("---")
	}
}
