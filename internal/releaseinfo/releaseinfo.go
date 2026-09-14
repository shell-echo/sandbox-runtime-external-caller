// Package releaseinfo contains source identities embedded into candidate-owned
// executables. The local defaults are self-asserted development identifiers,
// not independent release or provenance evidence.
package releaseinfo

import "github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"

var (
	CallerKind   = "release-id"
	CallerValue  = "local-development"
	AdapterKind  = "release-id"
	AdapterValue = "local-development"
	GatewayKind  = "release-id"
	GatewayValue = "local-development"
)

func Caller() protocol.SourceIdentity {
	return protocol.SourceIdentity{Kind: CallerKind, Value: CallerValue, Immutable: true}
}

func Adapter() protocol.SourceIdentity {
	return protocol.SourceIdentity{Kind: AdapterKind, Value: AdapterValue, Immutable: true}
}

func Gateway() protocol.SourceIdentity {
	return protocol.SourceIdentity{Kind: GatewayKind, Value: GatewayValue, Immutable: true}
}
