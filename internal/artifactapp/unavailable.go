// Package artifactapp defines fail-closed executable behavior until the
// private caller/Gateway composition protocol is implemented.
package artifactapp

const (
	ExitUsage       = 64
	ExitUnavailable = 69
)

// Unavailable rejects every argument and otherwise exits without reading or
// writing process streams. It prevents a skeleton artifact from being mistaken
// for an operational caller or Gateway.
func Unavailable(arguments []string) int {
	if len(arguments) != 0 {
		return ExitUsage
	}
	return ExitUnavailable
}
