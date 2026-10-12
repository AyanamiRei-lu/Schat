// Package version holds build identity information for the relay server.
package version

import (
	"fmt"
	"runtime"
)

// These are overridden at build time with:
//
//	go build -ldflags "-X github.com/schat/schat/server/internal/version.Version=..."
const (
	// Version is the semantic version of the server.
	Version = "0.1.0-alpha"

	// Protocol is the SCS-1 revision this server relays. The server does not
	// implement the protocol, but it refuses envelopes stamped with a version it
	// does not know how to route.
	Protocol = "SCS-1/v1"

	// Commit is the source revision the binary was built from.
	Commit = "unknown"
)

// String renders a one-line build identity.
func String() string {
	return fmt.Sprintf("schat-server %s (protocol %s, commit %s, %s %s/%s)",
		Version, Protocol, Commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
