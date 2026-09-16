package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/releasebuild"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	flags := flag.NewFlagSet("release-artifacts", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	source := flags.String("source-root", "", "absolute candidate source root")
	output := flags.String("output", "", "absolute new release bundle directory")
	verify := flags.String("verify", "", "absolute existing release bundle directory")
	goBinary := flags.String("go", "go", "Go toolchain executable")
	goos := flags.String("goos", "", "target GOOS (darwin or linux)")
	goarch := flags.String("goarch", "", "target GOARCH (amd64 or arm64)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 64
	}
	if *verify != "" {
		if *source != "" || *output != "" {
			return 64
		}
		root, err := filepath.Abs(*verify)
		if err != nil {
			return 70
		}
		manifest, err := releasebuild.Verify(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "release bundle verification failed")
			return 70
		}
		fmt.Println(manifest.ManifestDigest)
		return 0
	}
	if *source == "" || *output == "" {
		return 64
	}
	sourceRoot, err := filepath.Abs(*source)
	if err != nil {
		return 70
	}
	outputRoot, err := filepath.Abs(*output)
	if err != nil {
		return 70
	}
	manifest, err := releasebuild.Build(context.Background(), releasebuild.Options{
		SourceRoot: sourceRoot, OutputDir: outputRoot, GoBinary: *goBinary, GOOS: *goos, GOARCH: *goarch,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "release bundle build failed")
		return 70
	}
	fmt.Println(manifest.ManifestDigest)
	return 0
}
