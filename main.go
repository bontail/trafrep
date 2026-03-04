package main

import (
	"log"

	"trafRep/cmd"
)

func main() {
	cmd.RootCmd.AddCommand(cmd.PrintCmd)
	cmd.RootCmd.AddCommand(cmd.ReplayCmd)
	cmd.RootCmd.AddCommand(cmd.CompareCmd)
	err := cmd.RootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
