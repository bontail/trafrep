package pcap

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TCPPacket представляет сетевой TCP-пакет, извлечённый из pcap.
// Поля содержат метаданные пакета: время прихода, полезную нагрузку,
// IP-адреса источника и назначения и соответствующие порты.
type TCPPacket struct {
	Timestamp  time.Time
	Data       []byte
	IPSource   string
	IPDest     string
	PortSource uint16
	PortDest   uint16
}

// ExtractPackets читает пакеты из handle и возвращает TCPPacket,
// соответствующие заданному filterIP и filterPort.
// Retransmission-пакеты (seq < ожидаемого следующего) пропускаются.
func ExtractPackets(handle *pcap.Handle, filterIP net.IP, filterPort uint16) []TCPPacket {
	var packets []TCPPacket
	// nextSeq хранит следующий ожидаемый sequence number для каждого направления потока.
	nextSeq := make(map[string]uint32)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok || tcp == nil || len(tcp.Payload) == 0 {
			continue
		}

		ipSrc, ipDst := getIPs(packet.NetworkLayer())
		if !((uint16(tcp.SrcPort) == filterPort && (ipSrc.Equal(filterIP) || filterIP == nil)) ||
			(uint16(tcp.DstPort) == filterPort && (ipDst.Equal(filterIP) || filterIP == nil))) {
			continue
		}

		key := fmt.Sprintf("%s:%d->%s:%d", ipSrc, uint16(tcp.SrcPort), ipDst, uint16(tcp.DstPort))
		seq := tcp.Seq
		payloadLen := uint32(len(tcp.Payload))

		if expected, seen := nextSeq[key]; seen {
			if seq < expected {
				continue
			}
		}
		nextSeq[key] = seq + payloadLen

		packets = append(packets, TCPPacket{
			Timestamp:  packet.Metadata().Timestamp,
			Data:       tcp.Payload,
			IPSource:   ipSrc.String(),
			IPDest:     ipDst.String(),
			PortSource: uint16(tcp.SrcPort),
			PortDest:   uint16(tcp.DstPort),
		})
	}
	return packets
}

// getIPs извлекает IP-адреса источника и назначения из переданного networkLayer.
// Поддерживаются слои *layers.IPv4 и *layers.IPv6.
func getIPs(networkLayer gopacket.NetworkLayer) (src net.IP, dst net.IP) {
	switch layer := networkLayer.(type) {
	case *layers.IPv4:
		return layer.SrcIP, layer.DstIP
	case *layers.IPv6:
		return layer.SrcIP, layer.DstIP
	default:
		return nil, nil
	}
}
