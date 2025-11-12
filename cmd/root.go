package cmd

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var PcapPath string
var PcapPostgresHost string
var PcapPostgresPort uint16

var RootCmd = &cobra.Command{
	Use:   "app",
	Short: "Трафик репортер",
	Long:  "Приложение для анализа и воспроизведения pcap файлов.",
}

func init() {
	RootCmd.PersistentFlags().StringVar(&PcapPath, "pcap", "", "Путь к pcap файлу")
	err := RootCmd.MarkPersistentFlagRequired("pcap")
	if err != nil {
		log.Fatal(err)
		return
	}

	RootCmd.PersistentFlags().StringVarP(&PcapPostgresHost, "host", "H", "::1", "PostgreSQL хост в pcap файле")
	RootCmd.PersistentFlags().Uint16VarP(&PcapPostgresPort, "port", "P", 5432, "PostgreSQL port в pcap файле")
}

// GetPcapHandle открывает pcap файл по пути из флагов и возвращает *pcap.Handle.
func GetPcapHandle() (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(PcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	return handle, nil
}
