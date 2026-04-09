package main

import (
	"log"

	"trafRep/cmd"
)

func main() {
	cmd.RootCmd.AddCommand(cmd.PrintCmd)
	cmd.RootCmd.AddCommand(cmd.ReplayCmd)
	cmd.RootCmd.AddCommand(cmd.CompareCmd)
	cmd.RootCmd.AddCommand(cmd.CompareStatsCmd)
	cmd.RootCmd.AddCommand(cmd.CollectInfoCmd)
	err := cmd.RootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
