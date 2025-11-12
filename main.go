package main

import (
	"log"

	"trafRep/cmd"
)

func main() {

	cmd.RootCmd.AddCommand(cmd.PrintCmd)
	cmd.RootCmd.AddCommand(cmd.ReplayCmd)
	err := cmd.RootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
