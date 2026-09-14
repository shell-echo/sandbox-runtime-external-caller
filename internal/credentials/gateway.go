package credentials

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const GatewayCredentialType = "sandbox-gateway-client-credentials-v1"

var (
	ErrGatewayCredentialDocument = errors.New("gateway credential document is invalid")
	ErrGatewayEndpoint           = errors.New("gateway endpoint is unsupported by this candidate")
)

type GatewayCredentialDocument struct {
	FormatVersion       int    `json:"format_version"`
	CredentialType      string `json:"credential_type"`
	Actor               string `json:"actor"`
	ControllerSubject   string `json:"controller_subject"`
	CertificateChainPEM string `json:"certificate_chain_pem"`
	PrivateKeyPEM       string `json:"private_key_pem"`
}

type GatewayAccess struct {
	Actor             string
	ControllerSubject string
	TLSConfig         *tls.Config
}

func BuildGatewayAccess(endpoint, expectedActor string, credentialPayload, trustPayload []byte) (*GatewayAccess, error) {
	if protocol.ValidateGatewayEndpoint(endpoint) != nil {
		return nil, ErrGatewayEndpoint
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || parsedEndpoint.Scheme != "https" || parsedEndpoint.Hostname() == "" {
		return nil, ErrGatewayEndpoint
	}
	document, err := decodeGatewayCredential(credentialPayload)
	if err != nil || document.Actor != expectedActor || (document.Actor != "controller_a" && document.Actor != "controller_b") {
		return nil, ErrGatewayCredentialDocument
	}
	certificate, err := tls.X509KeyPair([]byte(document.CertificateChainPEM), []byte(document.PrivateKeyPEM))
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrClientCertificate
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !validClientLeaf(leaf, document.ControllerSubject, time.Now()) {
		return nil, ErrClientCertificate
	}
	certificate.Leaf = leaf
	roots, err := parseTrustBundle(trustPayload)
	if err != nil {
		return nil, err
	}
	return &GatewayAccess{
		Actor: document.Actor, ControllerSubject: document.ControllerSubject,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: parsedEndpoint.Hostname(), RootCAs: roots,
			Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"},
		},
	}, nil
}

func BuildGatewayAccessFromBundle(bundle *Bundle, endpoint, actor string) (*GatewayAccess, error) {
	if bundle == nil {
		return nil, ErrUnknownChannel
	}
	channelID := ""
	switch actor {
	case "controller_a":
		channelID = "gateway-controller-a"
	case "controller_b":
		channelID = "gateway-controller-b"
	default:
		return nil, ErrGatewayCredentialDocument
	}
	var access *GatewayAccess
	err := bundle.UsePair(channelID, "gateway-trust", func(credentialPayload, trustPayload []byte) error {
		var err error
		access, err = BuildGatewayAccess(endpoint, actor, credentialPayload, trustPayload)
		return err
	})
	if err != nil {
		return nil, err
	}
	return access, nil
}

func decodeGatewayCredential(payload []byte) (GatewayCredentialDocument, error) {
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		return GatewayCredentialDocument{}, ErrGatewayCredentialDocument
	}
	defer clear(canonical)
	var raw map[string]json.RawMessage
	if json.Unmarshal(canonical, &raw) != nil || !hasExactKeys(raw, []string{
		"format_version", "credential_type", "actor", "controller_subject", "certificate_chain_pem", "private_key_pem",
	}) {
		return GatewayCredentialDocument{}, ErrGatewayCredentialDocument
	}
	var document GatewayCredentialDocument
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return GatewayCredentialDocument{}, ErrGatewayCredentialDocument
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || document.FormatVersion != 1 || document.CredentialType != GatewayCredentialType || document.Actor == "" || document.ControllerSubject == "" || document.CertificateChainPEM == "" || document.PrivateKeyPEM == "" {
		return GatewayCredentialDocument{}, ErrGatewayCredentialDocument
	}
	return document, nil
}
