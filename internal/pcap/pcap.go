package pcap

import (
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
// Функция возвращает только те пакеты,
// у которых src или dst совпадает с filterIP и соответствующий порт равен filterPort.
func ExtractPackets(handle *pcap.Handle, filterIP net.IP, filterPort uint16) []TCPPacket {
	if filterIP == nil {
		return nil
	}

	var packets []TCPPacket
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok || tcp == nil || len(tcp.Payload) == 0 {
			continue
		}

		ipSrc, ipDst := getIPs(packet.NetworkLayer())
		if !((uint16(tcp.SrcPort) == filterPort && ipSrc.Equal(filterIP)) ||
			(uint16(tcp.DstPort) == filterPort && ipDst.Equal(filterIP))) {
			continue
		}

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
// Возвращает src и dst как net.IP. Для неподдерживаемых или отсутствующих сетевых слоёв
// возвращает (nil, nil).
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
