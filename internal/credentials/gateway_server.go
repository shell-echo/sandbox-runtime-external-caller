package credentials

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/jcs"
	"github.com/shell-echo/sandbox-runtime-external-caller/internal/protocol"
)

const GatewayServerCredentialType = "sandbox-gateway-server-credentials-v1"

var (
	ErrGatewayServerDocument  = errors.New("gateway server credential document is invalid")
	ErrGatewayServerIdentity  = errors.New("gateway server identity is invalid")
	ErrGatewayIdentityBinding = errors.New("gateway credential identities do not bind")
)

type GatewayControllerSubjects struct {
	ControllerA string `json:"controller_a"`
	ControllerB string `json:"controller_b"`
}

type GatewayServerCredentialDocument struct {
	FormatVersion           int                       `json:"format_version"`
	CredentialType          string                    `json:"credential_type"`
	CertificateChainPEM     string                    `json:"certificate_chain_pem"`
	PrivateKeyPEM           string                    `json:"private_key_pem"`
	ClientCACertificatesPEM string                    `json:"client_ca_certificates_pem"`
	ControllerSubjects      GatewayControllerSubjects `json:"controller_subjects"`
}

// GatewayServerIdentity owns its parsed private key. Destroy must run after
// any TLS user has stopped; it is not safe concurrently with TLS handshakes.
// ExpiresAt bounds the lifetime of a future serving process, not just startup.
type GatewayServerIdentity struct {
	TLSConfig          *tls.Config
	ControllerSubjects GatewayControllerSubjects
	ExpiresAt          time.Time
	clientRoots        *x509.CertPool
	publicKey          []byte
}

func (identity *GatewayServerIdentity) Destroy() {
	if identity == nil {
		return
	}
	if identity.TLSConfig != nil {
		for i := range identity.TLSConfig.Certificates {
			clearTLSKey(&identity.TLSConfig.Certificates[i])
		}
	}
	identity.TLSConfig = nil
	identity.clientRoots = nil
	identity.publicKey = nil
	identity.ControllerSubjects = GatewayControllerSubjects{}
	identity.ExpiresAt = time.Time{}
}

func BuildGatewayServerIdentityFromBundle(bundle *Bundle, endpoint string) (*GatewayServerIdentity, error) {
	if bundle == nil {
		return nil, ErrGatewayServerDocument
	}
	var identity *GatewayServerIdentity
	err := bundle.UsePair("gateway-server", "gateway-trust", func(secret, trust []byte) error {
		var err error
		identity, err = BuildGatewayServerIdentity(endpoint, secret, trust)
		return err
	})
	return identity, err
}

// BuildGatewayServerIdentity performs no I/O. Only injected trust anchors are
// used. Errors intentionally contain no parser, certificate, or endpoint data.
func BuildGatewayServerIdentity(endpoint string, secret, trust []byte) (*GatewayServerIdentity, error) {
	if protocol.ValidateGatewayEndpoint(endpoint) != nil {
		return nil, ErrGatewayEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" {
		return nil, ErrGatewayEndpoint
	}
	document, err := decodeGatewayServerCredential(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	chain, err := strictCertificates([]byte(document.CertificateChainPEM))
	if err != nil {
		return nil, ErrGatewayServerIdentity
	}
	keyBlock, rest, err := strictPEM([]byte(document.PrivateKeyPEM), "PRIVATE KEY")
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrGatewayServerIdentity
	}
	defer clear(keyBlock.Bytes)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, ErrGatewayServerIdentity
	}
	key, ok := parsedKey.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, ErrGatewayServerIdentity
	}
	keepKey := false
	defer func() {
		if !keepKey {
			clear(key)
		}
	}()
	leaf := chain[0]
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, key.Public().(ed25519.PublicKey)) || leaf.IsCA ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.ExtKeyUsage) != 1 ||
		leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		!exactServerSAN(leaf, parsed.Hostname()) {
		return nil, ErrGatewayServerIdentity
	}
	roots, serverRoots, err := strictRoots(trust, now)
	if err != nil {
		return nil, ErrGatewayServerIdentity
	}
	clientRoots, clientCerts, err := strictRoots([]byte(document.ClientCACertificatesPEM), now)
	if err != nil {
		return nil, ErrGatewayServerIdentity
	}
	verified, err := verifyChain(chain, roots, x509.ExtKeyUsageServerAuth, parsed.Hostname(), now)
	if err != nil {
		return nil, ErrGatewayServerIdentity
	}
	expires := leaf.NotAfter
	for _, certificates := range [][]*x509.Certificate{verified, serverRoots, clientCerts} {
		for _, certificate := range certificates {
			if certificate.NotAfter.Before(expires) {
				expires = certificate.NotAfter
			}
			if bytes.Equal(certificate.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) && certificate.IsCA {
				return nil, ErrGatewayServerIdentity
			}
		}
	}
	certificate := tls.Certificate{PrivateKey: key, Leaf: leaf}
	for _, item := range chain {
		certificate.Certificate = append(certificate.Certificate, item.Raw)
	}
	keepKey = true
	return &GatewayServerIdentity{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
		},
		ControllerSubjects: document.ControllerSubjects, ExpiresAt: expires,
		clientRoots: clientRoots, publicKey: leaf.RawSubjectPublicKeyInfo,
	}, nil
}

// ValidateGatewayIdentityBundle binds both controller chains/subjects and
// rejects Gateway key reuse with Provider TLS or Admission signing identities.
// It creates no Provider client and signs or sends no request.
func ValidateGatewayIdentityBundle(bundle *Bundle, endpoint string) error {
	identity, err := BuildGatewayServerIdentityFromBundle(bundle, endpoint)
	if err != nil {
		return err
	}
	defer identity.Destroy()
	gatewayKeys := [][]byte{identity.publicKey}
	now := time.Now()
	for _, selected := range []struct{ channel, actor, subject string }{
		{"gateway-controller-a", "controller_a", identity.ControllerSubjects.ControllerA},
		{"gateway-controller-b", "controller_b", identity.ControllerSubjects.ControllerB},
	} {
		err := bundle.Use(selected.channel, func(payload []byte) error {
			if len(payload) > credentialChannelBytes {
				return ErrGatewayIdentityBinding
			}
			document, err := decodeGatewayCredential(payload)
			if err != nil || document.Actor != selected.actor || document.ControllerSubject != selected.subject {
				return ErrGatewayIdentityBinding
			}
			chain, err := strictClientPair(document.CertificateChainPEM, document.PrivateKeyPEM, selected.subject, now)
			if err != nil {
				return ErrGatewayIdentityBinding
			}
			if _, err := verifyChain(chain, identity.clientRoots, x509.ExtKeyUsageClientAuth, "", now); err != nil {
				return ErrGatewayIdentityBinding
			}
			key := chain[0].RawSubjectPublicKeyInfo
			if containsKey(gatewayKeys, key) {
				return ErrGatewayIdentityBinding
			}
			gatewayKeys = append(gatewayKeys, key)
			return nil
		})
		if err != nil {
			return ErrGatewayIdentityBinding
		}
	}
	for _, selected := range []struct{ channel, actor string }{
		{"provider-controller-a", "controller_a"}, {"provider-controller-b", "controller_b"},
		{"provider-same-ca-unadmitted", "same_ca_unadmitted"},
	} {
		err := bundle.Use(selected.channel, func(payload []byte) error {
			if len(payload) > credentialChannelBytes {
				return ErrGatewayIdentityBinding
			}
			document, err := decodeProviderCredential(payload)
			if err != nil || document.Actor != selected.actor {
				return ErrGatewayIdentityBinding
			}
			chain, err := strictClientPair(document.CertificateChainPEM, document.PrivateKeyPEM, document.ControllerSubject, now)
			if err != nil || containsKey(gatewayKeys, chain[0].RawSubjectPublicKeyInfo) {
				return ErrGatewayIdentityBinding
			}
			if selected.actor == "same_ca_unadmitted" {
				if document.Admission != nil {
					return ErrGatewayIdentityBinding
				}
				return nil
			}
			if document.Admission == nil {
				return ErrGatewayIdentityBinding
			}
			key, err := decodeEd25519PrivateKey(document.Admission.Ed25519PrivateKey)
			if err != nil {
				return ErrGatewayIdentityBinding
			}
			defer clear(key)
			derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
			defer clear(derived)
			if !bytes.Equal(key, derived) {
				return ErrGatewayIdentityBinding
			}
			public, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil || containsKey(gatewayKeys, public) {
				return ErrGatewayIdentityBinding
			}
			return nil
		})
		if err != nil {
			return ErrGatewayIdentityBinding
		}
	}
	return nil
}

func decodeGatewayServerCredential(payload []byte) (GatewayServerCredentialDocument, error) {
	if len(payload) == 0 || len(payload) > credentialChannelBytes {
		return GatewayServerCredentialDocument{}, ErrGatewayServerDocument
	}
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		return GatewayServerCredentialDocument{}, ErrGatewayServerDocument
	}
	defer clear(canonical)
	var raw map[string]json.RawMessage
	if json.Unmarshal(canonical, &raw) != nil {
		return GatewayServerCredentialDocument{}, ErrGatewayServerDocument
	}
	defer func() {
		for _, value := range raw {
			clear(value)
		}
	}()
	if !hasExactKeys(raw, []string{"format_version", "credential_type", "certificate_chain_pem", "private_key_pem", "client_ca_certificates_pem", "controller_subjects"}) {
		return GatewayServerCredentialDocument{}, ErrGatewayServerDocument
	}
	var subjects map[string]json.RawMessage
	if json.Unmarshal(raw["controller_subjects"], &subjects) != nil || !hasExactKeys(subjects, []string{"controller_a", "controller_b"}) {
		return GatewayServerCredentialDocument{}, ErrGatewayServerDocument
	}
	var document GatewayServerCredentialDocument
	if json.Unmarshal(canonical, &document) != nil || document.FormatVersion != 1 || document.CredentialType != GatewayServerCredentialType ||
		document.CertificateChainPEM == "" || document.PrivateKeyPEM == "" || document.ClientCACertificatesPEM == "" ||
		!validControllerSubject(document.ControllerSubjects.ControllerA) || !validControllerSubject(document.ControllerSubjects.ControllerB) ||
		document.ControllerSubjects.ControllerA == document.ControllerSubjects.ControllerB {
		return GatewayServerCredentialDocument{}, ErrGatewayServerDocument
	}
	return document, nil
}

func validControllerSubject(subject string) bool {
	u, err := url.Parse(subject)
	return err == nil && u.IsAbs() && u.Fragment == "" && len(subject) > 0
}

func strictPEM(payload []byte, blockType string) (*pem.Block, []byte, error) {
	trimmed := bytes.TrimSpace(payload)
	begin, end := []byte("-----BEGIN "+blockType+"-----"), []byte("-----END "+blockType+"-----")
	if !bytes.HasPrefix(trimmed, begin) {
		return nil, nil, ErrGatewayServerIdentity
	}
	last := bytes.Index(trimmed, end)
	if last < len(begin) {
		return nil, nil, ErrGatewayServerIdentity
	}
	segment := trimmed[:last+len(end)]
	if bytes.Contains(segment[len(begin):], []byte("-----BEGIN")) {
		return nil, nil, ErrGatewayServerIdentity
	}
	block, rest := pem.Decode(segment)
	if block == nil || block.Type != blockType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, ErrGatewayServerIdentity
	}
	return block, trimmed[last+len(end):], nil
}

func strictCertificates(payload []byte) ([]*x509.Certificate, error) {
	if len(payload) == 0 || len(payload) > credentialChannelBytes {
		return nil, ErrGatewayServerIdentity
	}
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(payload)) > 0 {
		if len(certificates) == 8 {
			return nil, ErrGatewayServerIdentity
		}
		block, rest, err := strictPEM(payload, "CERTIFICATE")
		if err != nil {
			return nil, err
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrGatewayServerIdentity
		}
		for _, previous := range certificates {
			if bytes.Equal(previous.Raw, certificate.Raw) {
				return nil, ErrGatewayServerIdentity
			}
		}
		certificates = append(certificates, certificate)
		payload = rest
	}
	if len(certificates) == 0 {
		return nil, ErrGatewayServerIdentity
	}
	return certificates, nil
}

func strictRoots(payload []byte, now time.Time) (*x509.CertPool, []*x509.Certificate, error) {
	certificates, err := strictCertificates(payload)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, nil, ErrGatewayServerIdentity
		}
		pool.AddCert(certificate)
	}
	return pool, certificates, nil
}

func verifyChain(chain []*x509.Certificate, roots *x509.CertPool, usage x509.ExtKeyUsage, hostname string, now time.Time) ([]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		if chain[i-1].CheckSignatureFrom(chain[i]) != nil {
			return nil, ErrGatewayServerIdentity
		}
		intermediates.AddCert(chain[i])
	}
	verified, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: hostname, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil || len(verified) == 0 {
		return nil, ErrGatewayServerIdentity
	}
	return verified[0], nil
}

func exactServerSAN(leaf *x509.Certificate, host string) bool {
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var sequence, name asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return false
		}
		rest, err = asn1.Unmarshal(sequence.Bytes, &name)
		if err != nil || len(rest) != 0 || name.Class != asn1.ClassContextSpecific || name.IsCompound {
			return false
		}
		if ip := net.ParseIP(host); ip != nil {
			return name.Tag == 7 && (len(name.Bytes) == 4 || len(name.Bytes) == 16) && ip.Equal(net.IP(name.Bytes))
		}
		return name.Tag == 2 && string(name.Bytes) == host
	}
	return false
}

func strictClientPair(certificatePEM, keyPEM, subject string, now time.Time) ([]*x509.Certificate, error) {
	chain, err := strictCertificates([]byte(certificatePEM))
	if err != nil || !validClientLeaf(chain[0], subject, now) {
		return nil, ErrGatewayIdentityBinding
	}
	// Preserve existing client key algorithm support while rejecting skipped or
	// additional PEM blocks. The server's key restriction is separate.
	validKey := false
	for _, kind := range []string{"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"} {
		block, rest, err := strictPEM([]byte(keyPEM), kind)
		if err == nil {
			clear(block.Bytes)
			validKey = len(bytes.TrimSpace(rest)) == 0
			break
		}
	}
	if !validKey {
		return nil, ErrGatewayIdentityBinding
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
	if err != nil {
		return nil, ErrGatewayIdentityBinding
	}
	clearTLSKey(&certificate)
	return chain, nil
}

func clearTLSKey(certificate *tls.Certificate) {
	if key, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(key)
	}
	certificate.PrivateKey = nil
}

func containsKey(keys [][]byte, value []byte) bool {
	for _, key := range keys {
		if bytes.Equal(key, value) {
			return true
		}
	}
	return false
}
