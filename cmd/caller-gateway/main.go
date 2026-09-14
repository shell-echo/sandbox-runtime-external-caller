package main

import (
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/gatewayapp"
)

func main() {
	os.Exit(gatewayapp.Run(os.Args[1:], os.Stdin, os.Stdout))
}
