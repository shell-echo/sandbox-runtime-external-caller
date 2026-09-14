package credentials

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/provider"
)

const ProviderCredentialType = "sandbox-provider-client-credentials-v1"

var (
	ErrCredentialDocument = errors.New("provider credential document is invalid")
	ErrTrustBundle        = errors.New("provider trust bundle is invalid")
	ErrClientCertificate  = errors.New("provider client certificate is invalid")
	ErrAdmissionKey       = errors.New("provider admission signing key is invalid")

	providerAudiencePattern = regexp.MustCompile(`^urn:shell-echo:sandbox-runtime:provider-instance:[A-Za-z0-9._:-]{1,200}$`)
)

type ProviderCredentialDocument struct {
	FormatVersion       int                      `json:"format_version"`
	CredentialType      string                   `json:"credential_type"`
	Actor               string                   `json:"actor"`
	ControllerSubject   string                   `json:"controller_subject"`
	CertificateChainPEM string                   `json:"certificate_chain_pem"`
	PrivateKeyPEM       string                   `json:"private_key_pem"`
	Admission           *ProviderAdmissionSecret `json:"admission"`
}

type ProviderAdmissionSecret struct {
	Issuer                   string `json:"issuer"`
	ProviderInstanceAudience string `json:"provider_instance_audience"`
	KeyID                    string `json:"key_id"`
	Ed25519PrivateKey        string `json:"ed25519_private_key_base64url"`
}

type ProviderAdmissionMaterial struct {
	Issuer                   string
	ProviderInstanceAudience string
	Signer                   *provider.Ed25519Signer
}

// ProviderAccess is one actor's caller-owned mTLS transport plus optional
// protected-admission signing material. The same-CA unadmitted actor has no
// admission material and can only exercise mTLS rejection behavior.
type ProviderAccess struct {
	Actor             string
	ControllerSubject string
	Admission         *ProviderAdmissionMaterial
	Client            *provider.Client
	Transport         *http.Transport
}

// BuildProviderAccessFromBundle selects the exact fixed Provider credential
// and trust channels for actor. It never falls back to another actor.
func BuildProviderAccessFromBundle(bundle *Bundle, origin, actor string) (*ProviderAccess, error) {
	if bundle == nil {
		return nil, ErrUnknownChannel
	}
	channelID := ""
	switch actor {
	case "controller_a":
		channelID = "provider-controller-a"
	case "controller_b":
		channelID = "provider-controller-b"
	case "same_ca_unadmitted":
		channelID = "provider-same-ca-unadmitted"
	default:
		return nil, ErrCredentialDocument
	}
	var access *ProviderAccess
	err := bundle.UsePair(channelID, "provider-trust", func(credentialPayload, trustPayload []byte) error {
		var err error
		access, err = BuildProviderAccess(origin, actor, credentialPayload, trustPayload)
		return err
	})
	if err != nil {
		return nil, err
	}
	return access, nil
}

func (a *ProviderAccess) AdmissionAuthority(providerRevision string) (provider.AdmissionAuthority, bool) {
	if a == nil || a.Admission == nil {
		return provider.AdmissionAuthority{}, false
	}
	return provider.AdmissionAuthority{
		Issuer:                   a.Admission.Issuer,
		ControllerSubject:        a.ControllerSubject,
		ProviderInstanceAudience: a.Admission.ProviderInstanceAudience,
		ProviderRevisionID:       providerRevision,
	}, true
}

func (a *ProviderAccess) Close() {
	if a == nil {
		return
	}
	if a.Transport != nil {
		a.Transport.CloseIdleConnections()
		if a.Transport.TLSClientConfig != nil {
			for index := range a.Transport.TLSClientConfig.Certificates {
				clearTLSKey(&a.Transport.TLSClientConfig.Certificates[index])
			}
			a.Transport.TLSClientConfig.Certificates = nil
			a.Transport.TLSClientConfig.RootCAs = nil
		}
	}
	if a.Admission != nil && a.Admission.Signer != nil {
		a.Admission.Signer.Destroy()
	}
	a.Admission = nil
	a.Client = nil
	a.Transport = nil
	a.Actor = ""
	a.ControllerSubject = ""
}

// BuildProviderAccess validates a private candidate credential document,
// binds its declared subject to exactly one client-auth URI SAN, constructs a
// no-proxy mTLS transport, and injects it into the clean-room Provider client.
func BuildProviderAccess(origin, expectedActor string, credentialPayload, trustPayload []byte) (*ProviderAccess, error) {
	document, err := decodeProviderCredential(credentialPayload)
	if err != nil || document.Actor != expectedActor || !validProviderActor(document.Actor) {
		return nil, ErrCredentialDocument
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

	serverName, err := providerServerName(origin)
	if err != nil {
		return nil, err
	}
	transport := newProviderTransport(serverName, certificate, roots)
	client, err := provider.NewClient(origin, transport)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}

	access := &ProviderAccess{
		Actor:             document.Actor,
		ControllerSubject: document.ControllerSubject,
		Client:            client,
		Transport:         transport,
	}
	if document.Actor == "same_ca_unadmitted" {
		if document.Admission != nil {
			access.Close()
			return nil, ErrCredentialDocument
		}
		return access, nil
	}
	if document.Admission == nil || !validIssuer(document.Admission.Issuer) || !providerAudiencePattern.MatchString(document.Admission.ProviderInstanceAudience) {
		access.Close()
		return nil, ErrCredentialDocument
	}
	privateKey, err := decodeEd25519PrivateKey(document.Admission.Ed25519PrivateKey)
	if err != nil {
		access.Close()
		return nil, err
	}
	signer, err := provider.NewEd25519Signer(document.Admission.KeyID, privateKey)
	zero(privateKey)
	if err != nil {
		access.Close()
		return nil, ErrAdmissionKey
	}
	access.Admission = &ProviderAdmissionMaterial{
		Issuer:                   document.Admission.Issuer,
		ProviderInstanceAudience: document.Admission.ProviderInstanceAudience,
		Signer:                   signer,
	}
	return access, nil
}

func decodeProviderCredential(payload []byte) (ProviderCredentialDocument, error) {
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		return ProviderCredentialDocument{}, ErrCredentialDocument
	}
	defer zero(canonical)
	if !hasExactCredentialKeys(canonical) {
		return ProviderCredentialDocument{}, ErrCredentialDocument
	}
	var document ProviderCredentialDocument
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return ProviderCredentialDocument{}, ErrCredentialDocument
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ProviderCredentialDocument{}, ErrCredentialDocument
	}
	if document.FormatVersion != 1 || document.CredentialType != ProviderCredentialType || document.Actor == "" || document.ControllerSubject == "" || document.CertificateChainPEM == "" || document.PrivateKeyPEM == "" {
		return ProviderCredentialDocument{}, ErrCredentialDocument
	}
	return document, nil
}

func hasExactCredentialKeys(document []byte) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil || !hasExactKeys(object, []string{
		"format_version", "credential_type", "actor", "controller_subject", "certificate_chain_pem", "private_key_pem", "admission",
	}) {
		return false
	}
	if bytes.Equal(object["admission"], []byte("null")) {
		return true
	}
	var admission map[string]json.RawMessage
	return json.Unmarshal(object["admission"], &admission) == nil && hasExactKeys(admission, []string{
		"issuer", "provider_instance_audience", "key_id", "ed25519_private_key_base64url",
	})
}

func hasExactKeys(object map[string]json.RawMessage, keys []string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func validProviderActor(actor string) bool {
	return actor == "controller_a" || actor == "controller_b" || actor == "same_ca_unadmitted"
}

func validClientLeaf(leaf *x509.Certificate, subject string, now time.Time) bool {
	if leaf == nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].Fragment != "" || !leaf.URIs[0].IsAbs() || leaf.URIs[0].String() != subject {
		return false
	}
	if len(leaf.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func parseTrustBundle(payload []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remainder := payload
	count := 0
	for len(bytes.TrimSpace(remainder)) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrTrustBundle
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrTrustBundle
		}
		pool.AddCert(certificate)
		count++
		remainder = rest
	}
	if count == 0 {
		return nil, ErrTrustBundle
	}
	return pool, nil
}

func providerServerName(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return "", provider.ErrInvalidOrigin
	}
	return parsed.Hostname(), nil
}

func newProviderTransport(serverName string, certificate tls.Certificate, roots *x509.CertPool) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ServerName:   serverName,
			RootCAs:      roots,
			Certificates: []tls.Certificate{certificate},
		},
	}
}

func decodeEd25519PrivateKey(encoded string) (ed25519.PrivateKey, error) {
	if encoded == "" || strings.Contains(encoded, "=") {
		return nil, ErrAdmissionKey
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		zero(decoded)
		return nil, ErrAdmissionKey
	}
	return ed25519.PrivateKey(decoded), nil
}

func validIssuer(issuer string) bool {
	if len(issuer) < 1 || len(issuer) > 200 {
		return false
	}
	if !strings.Contains(issuer, ":") {
		return true
	}
	parsed, err := url.Parse(issuer)
	return err == nil && parsed.IsAbs() && parsed.Fragment == ""
}
