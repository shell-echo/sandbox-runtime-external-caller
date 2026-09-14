// Package testcredentials generates ephemeral, independent test identities.
// Only tests import it; it never writes credentials to disk or connects to a
// service. Its document shapes are intentionally independent of runtime DTOs.
package testcredentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

type Fixture struct {
	Payloads                            map[string][]byte
	ServerCA, ClientCA                  *x509.Certificate
	ServerCAKey, ClientCAKey, ServerKey ed25519.PrivateKey
	ServerTemplate                      *x509.Certificate
	ProviderCA                          *x509.Certificate
	ProviderCAKey                       ed25519.PrivateKey
	ProviderAdmissionPublicKeys         map[string]ed25519.PublicKey
}

func New(t testing.TB) *Fixture {
	return NewForGatewayHost(t, "gateway.example")
}

// NewForGatewayHost creates test-only server material for an exact DNS name
// or IP address. Production packages must never import this helper.
func NewForGatewayHost(t testing.TB, host string) *Fixture {
	t.Helper()
	serverCA, serverCAKey := root(t, "server-root")
	clientCA, clientCAKey := root(t, "client-root")
	providerCA, providerCAKey := root(t, "provider-root")
	f := &Fixture{
		Payloads: make(map[string][]byte), ServerCA: serverCA, ServerCAKey: serverCAKey,
		ClientCA: clientCA, ClientCAKey: clientCAKey, ServerKey: Key(t), ProviderCA: providerCA,
		ProviderCAKey: providerCAKey, ProviderAdmissionPublicKeys: make(map[string]ed25519.PublicKey),
	}
	f.ServerTemplate = Template()
	f.ServerTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if address := net.ParseIP(host); address != nil {
		f.ServerTemplate.IPAddresses = []net.IP{address}
	} else {
		f.ServerTemplate.DNSNames = []string{host}
	}
	server, key := Issue(t, serverCA, serverCAKey, f.ServerTemplate, f.ServerKey)
	f.Payloads["gateway-server"] = JSON(t, map[string]any{
		"format_version": 1, "credential_type": "sandbox-gateway-server-credentials-v1",
		"certificate_chain_pem": server, "private_key_pem": key,
		"client_ca_certificates_pem": CertificatePEM(clientCA),
		"controller_subjects":        map[string]string{"controller_a": "spiffe://gateway/controller_a", "controller_b": "spiffe://gateway/controller_b"},
	})
	f.Payloads["gateway-trust"] = []byte(CertificatePEM(serverCA))
	f.Payloads["provider-trust"] = []byte(CertificatePEM(providerCA))
	for _, actor := range []string{"controller_a", "controller_b", "same_ca_unadmitted"} {
		providerSubject := "spiffe://provider/" + actor
		leaf := Template()
		u, _ := url.Parse(providerSubject)
		leaf.URIs = []*url.URL{u}
		certificate, key := Issue(t, providerCA, providerCAKey, leaf, Key(t))
		var admission any
		if actor != "same_ca_unadmitted" {
			admissionKey := Key(t)
			f.ProviderAdmissionPublicKeys[actor] = append(ed25519.PublicKey(nil), admissionKey.Public().(ed25519.PublicKey)...)
			admission = map[string]any{
				"issuer": "https://caller.example.test/control", "provider_instance_audience": "urn:shell-echo:sandbox-runtime:provider-instance:test",
				"key_id": "test-key", "ed25519_private_key_base64url": base64.RawURLEncoding.EncodeToString(admissionKey),
			}
		}
		channel := map[string]string{"controller_a": "provider-controller-a", "controller_b": "provider-controller-b", "same_ca_unadmitted": "provider-same-ca-unadmitted"}[actor]
		f.Payloads[channel] = JSON(t, map[string]any{
			"format_version": 1, "credential_type": "sandbox-provider-client-credentials-v1", "actor": actor,
			"controller_subject": providerSubject, "certificate_chain_pem": certificate, "private_key_pem": key, "admission": admission,
		})
		if actor == "same_ca_unadmitted" {
			continue
		}
		subject := "spiffe://gateway/" + actor
		leaf = Template()
		u, _ = url.Parse(subject)
		leaf.URIs = []*url.URL{u}
		certificate, key = Issue(t, clientCA, clientCAKey, leaf, Key(t))
		channel = map[string]string{"controller_a": "gateway-controller-a", "controller_b": "gateway-controller-b"}[actor]
		f.Payloads[channel] = JSON(t, map[string]any{
			"format_version": 1, "credential_type": "sandbox-gateway-client-credentials-v1", "actor": actor,
			"controller_subject": subject, "certificate_chain_pem": certificate, "private_key_pem": key,
		})
	}
	t.Cleanup(func() {
		for _, payload := range f.Payloads {
			clear(payload)
		}
	})
	return f
}

func (f *Fixture) ProviderServerCertificate(t testing.TB, host string) tls.Certificate {
	t.Helper()
	if f == nil || f.ProviderCA == nil || len(f.ProviderCAKey) == 0 {
		t.Fatal("Provider test authority is unavailable")
	}
	template := Template()
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if address := net.ParseIP(host); address != nil {
		template.IPAddresses = []net.IP{address}
	} else {
		template.DNSNames = []string{host}
	}
	certificatePEM, keyPEM := Issue(t, f.ProviderCA, f.ProviderCAKey, template, Key(t))
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func Template() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

func Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	return key
}

func Issue(t testing.TB, ca *x509.Certificate, issuerKey ed25519.PrivateKey, leaf *x509.Certificate, key ed25519.PrivateKey) (string, string) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func CertificatePEM(certificate *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
}

func JSON(t testing.TB, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func root(t testing.TB, name string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	key := Key(t)
	template := Template()
	template.SerialNumber = big.NewInt(1)
	template.Subject = pkix.Name{CommonName: name}
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign
	template.ExtKeyUsage = nil
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}
