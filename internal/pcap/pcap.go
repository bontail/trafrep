package pcap

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"trafRep/internal/models"
)

// ExtractPackets читает пакеты из handle и возвращает PostgresTCPPacket,
// соответствующие заданному filterIP и filterPort.
// filterIP должен быть корректным net.IP; функция возвращает только те пакеты,
// у которых src или dst совпадает с filterIP и соответствующий порт равен filterPort.
func ExtractPackets(handle *pcap.Handle, filterIP net.IP, filterPort uint16) []models.PostgresTCPPacket {
	if filterIP == nil {
		return nil
	}

	var packets []models.PostgresTCPPacket
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()
		if networkLayer == nil || transportLayer == nil {
			continue
		}
		tcp, ok := transportLayer.(*layers.TCP)
		if !ok {
			continue
		}
		if len(tcp.Payload) == 0 {
			continue
		}

		var ipSrc net.IP
		var ipDst net.IP
		switch layer := networkLayer.(type) {
		case *layers.IPv4:
			ipSrc = layer.SrcIP
			ipDst = layer.DstIP
		case *layers.IPv6:
			ipSrc = layer.SrcIP
			ipDst = layer.DstIP
		}

		if !((uint16(tcp.SrcPort) == filterPort && ipSrc.Equal(filterIP)) ||
			(uint16(tcp.DstPort) == filterPort && ipDst.Equal(filterIP))) {
			continue
		}

		packets = append(packets, models.PostgresTCPPacket{
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
