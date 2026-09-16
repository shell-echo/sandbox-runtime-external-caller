package main

import (
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "hold" {
		for {
			time.Sleep(time.Hour)
		}
	}
	child := exec.Command(os.Args[0], "hold")
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if child.Start() != nil {
		os.Exit(1)
	}
	_, _ = os.Stdout.WriteString("ready\n")
}
