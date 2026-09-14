package credentials

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

func TestBuildGatewayAccessBindsActorSubjectAndTLS(t *testing.T) {
	payload, trust := testGatewayCredential(t, "controller_a", "spiffe://gateway/controller-a", clientLeafOptions{})
	access, err := BuildGatewayAccess("https://gateway.example:8443/tunnel", "controller_a", payload, trust)
	if err != nil {
		t.Fatal(err)
	}
	if access.Actor != "controller_a" || access.ControllerSubject != "spiffe://gateway/controller-a" || access.TLSConfig == nil {
		t.Fatalf("GatewayAccess = %#v", access)
	}
	config := access.TLSConfig
	if config.ServerName != "gateway.example" || config.RootCAs == nil || len(config.Certificates) != 1 || len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
		t.Fatalf("gateway TLS config = %#v", config)
	}
}

func TestBuildGatewayAccessFromBundleUsesExactActorChannel(t *testing.T) {
	controllerA, trust := testGatewayCredential(t, "controller_a", "spiffe://gateway/controller-a", clientLeafOptions{})
	controllerB, _ := testGatewayCredential(t, "controller_b", "spiffe://gateway/controller-b", clientLeafOptions{})
	bundle := &Bundle{payloads: map[string][]byte{
		"gateway-controller-a": controllerA,
		"gateway-controller-b": controllerB,
		"gateway-trust":        trust,
	}, total: len(controllerA) + len(controllerB) + len(trust)}
	defer bundle.Destroy()

	access, err := BuildGatewayAccessFromBundle(bundle, "https://gateway.example/tunnel", "controller_b")
	if err != nil {
		t.Fatal(err)
	}
	if access.Actor != "controller_b" || access.ControllerSubject != "spiffe://gateway/controller-b" {
		t.Fatalf("selected access = %#v", access)
	}
	if _, err := BuildGatewayAccessFromBundle(bundle, "https://gateway.example/tunnel", "unknown"); !errors.Is(err, ErrGatewayCredentialDocument) {
		t.Fatalf("unknown actor error = %v", err)
	}
}

func TestBuildGatewayAccessRejectsClosedDocumentAndUnsupportedTransport(t *testing.T) {
	valid, trust := testGatewayCredential(t, "controller_a", "spiffe://gateway/controller-a", clientLeafOptions{})
	tests := []struct {
		name     string
		endpoint string
		actor    string
		payload  []byte
		want     error
	}{
		{name: "actor mismatch", endpoint: "https://gateway.example/tunnel", actor: "controller_b", payload: valid, want: ErrGatewayCredentialDocument},
		{name: "unknown member", endpoint: "https://gateway.example/tunnel", actor: "controller_a", payload: insertJSONMember(valid, `"sandbox_id":"forbidden-correlation"`), want: ErrGatewayCredentialDocument},
		{name: "duplicate member", endpoint: "https://gateway.example/tunnel", actor: "controller_a", payload: insertJSONMember(valid, `"actor":"controller_a"`), want: ErrGatewayCredentialDocument},
		{name: "server identity in client payload", endpoint: "https://gateway.example/tunnel", actor: "controller_a", payload: insertJSONMember(valid, `"server_credentials":{"private_key_pem":"synthetic-forbidden-value"}`), want: ErrGatewayCredentialDocument},
		{name: "wss not implemented", endpoint: "wss://gateway.example/tunnel", actor: "controller_a", payload: valid, want: ErrGatewayEndpoint},
		{name: "endpoint query", endpoint: "https://gateway.example/tunnel?session=forbidden", actor: "controller_a", payload: valid, want: ErrGatewayEndpoint},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access, err := BuildGatewayAccess(test.endpoint, test.actor, test.payload, trust)
			if access != nil {
				t.Fatal("rejected Gateway credential produced access")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("BuildGatewayAccess() error = %v, want %v", err, test.want)
			}
		})
	}
}

func testGatewayCredential(t *testing.T, actor, subject string, options clientLeafOptions) ([]byte, []byte) {
	t.Helper()
	providerPayload, trust, _ := testProviderCredential(t, actor, subject, options)
	var providerDocument ProviderCredentialDocument
	if err := json.Unmarshal(providerPayload, &providerDocument); err != nil {
		t.Fatal(err)
	}
	document := GatewayCredentialDocument{
		FormatVersion: 1, CredentialType: GatewayCredentialType, Actor: actor,
		ControllerSubject: subject, CertificateChainPEM: providerDocument.CertificateChainPEM,
		PrivateKeyPEM: providerDocument.PrivateKeyPEM,
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.ValidateGatewayEndpoint("https://gateway.example/tunnel") != nil {
		t.Fatal("test endpoint no longer satisfies locked protocol")
	}
	return payload, trust
}
