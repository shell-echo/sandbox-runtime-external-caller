package artifactapp

import "testing"

func TestUnavailableArtifactFailsClosed(t *testing.T) {
	if code := Unavailable(nil); code != ExitUnavailable {
		t.Fatalf("Unavailable(nil) = %d", code)
	}
	if code := Unavailable([]string{"forbidden-correlation"}); code != ExitUsage {
		t.Fatalf("Unavailable(argument) = %d", code)
	}
}
