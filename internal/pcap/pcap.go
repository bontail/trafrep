package pcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"trafRep/internal/models"
)

// ExtractPackets читает пакеты из handle и возвращает TCP-пакеты,
// которые связаны с filterHost (если указан) и/или имеют порт filterPort.
func ExtractPackets(handle *pcap.Handle, filterHost string, filterPort int) []models.TCPPacket {
	var packets []models.TCPPacket
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
		var ipSrc, ipDst string
		switch layer := networkLayer.(type) {
		case *layers.IPv4:
			ipSrc = layer.SrcIP.String()
			ipDst = layer.DstIP.String()
		case *layers.IPv6:
			ipSrc = layer.SrcIP.String()
			ipDst = layer.DstIP.String()
		}
		portSrc := uint16(tcp.SrcPort)
		portDest := uint16(tcp.DstPort)

		// порт должен совпадать хотя бы у одной стороны
		if int(portDest) != filterPort && int(portSrc) != filterPort {
			continue
		}

		// если задан хост — одна из сторон должна совпадать
		if filterHost != "" && filterHost != "0.0.0.0" {
			if ipSrc != filterHost && ipDst != filterHost {
				continue
			}
		}

		packets = append(packets, models.TCPPacket{
			Timestamp:    packet.Metadata().Timestamp,
			Data:         tcp.Payload,
			IPSource:     ipSrc,
			IPDest:       ipDst,
			PortSource:   portSrc,
			PortDest:     portDest,
			IsPostgreSQL: true,
		})
	}
	return packets
}
