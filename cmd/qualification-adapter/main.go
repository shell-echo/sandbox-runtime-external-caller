package main

import (
	"context"
	"os"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/adapterapp"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/callerprocess"
)

func main() {
	os.Exit(adapterapp.RunWithCaller(context.Background(), os.Args[1:], os.Stdin, os.Stdout, callerprocess.NewSiblingRunner()))
}
