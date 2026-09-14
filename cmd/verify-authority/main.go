package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/authority"
)

func main() {
	sourceRoot := flag.String("source-root", ".", "external caller repository root")
	providerSourceRoot := flag.String("provider-source-root", "", "sandbox-runtime source root containing locked public authorities")
	flag.Parse()
	if flag.NArg() != 0 || *providerSourceRoot == "" {
		fmt.Fprintln(os.Stderr, "usage: verify-authority -provider-source-root PATH [-source-root PATH]")
		os.Exit(2)
	}
	lockFile := filepath.Join(*sourceRoot, authority.LockPath)
	if err := authority.Verify(*providerSourceRoot, lockFile); err != nil {
		fmt.Fprintln(os.Stderr, "authority verification failed:", err)
		os.Exit(1)
	}
	fmt.Println("authority inputs verified; no external caller artifact or qualification result claimed")
}
