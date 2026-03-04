package cmd

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

// PcapPath — путь к pcap файлу, задаётся флагом --pcap.
var PcapPath string

// PcapPostgresHost — IP-адрес PostgreSQL сервера для фильтрации пакетов, задаётся флагом --host.
var PcapPostgresHost string

// PcapPostgresPort — порт PostgreSQL сервера для фильтрации пакетов, задаётся флагом --port.
var PcapPostgresPort uint16

// RootCmd — корневая команда CLI; все подкоманды (print, replay, compare) регистрируются как её дочерние элементы.
var RootCmd = &cobra.Command{
	Use:   "app",
	Short: "Трафик повторитель",
	Long:  "Приложение для анализа и воспроизведения pcap файлов.",
}

func init() {
	RootCmd.PersistentFlags().StringVar(&PcapPath, "pcap", "", "Путь к pcap файлу")
	RootCmd.PersistentFlags().StringVar(&PcapPostgresHost, "host", "", "PostgreSQL хост в pcap файле")
	RootCmd.PersistentFlags().Uint16Var(&PcapPostgresPort, "port", 5432, "PostgreSQL port в pcap файле")
}

// GetPcapHandle открывает pcap файл по пути из флагов и возвращает *pcap.Handle.
func GetPcapHandle() (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(PcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	return handle, nil
}
