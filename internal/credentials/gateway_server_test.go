package credentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-external-caller/internal/testcredentials"
)

func TestGatewayServerIdentityLoadsAndClearsOwnedKey(t *testing.T) {
	f := testcredentials.New(t)
	identity, err := BuildGatewayServerIdentity("https://gateway.example/tunnel", f.Payloads["gateway-server"], f.Payloads["gateway-trust"])
	if err != nil {
		t.Fatal(err)
	}
	config := identity.TLSConfig
	if config.MinVersion != tls.VersionTLS12 || config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil ||
		len(config.Certificates) != 1 || len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" ||
		!identity.ExpiresAt.After(time.Now()) || identity.ControllerSubjects.ControllerA != "spiffe://gateway/controller_a" {
		t.Fatal("server TLS identity is incomplete")
	}
	retained := config.Certificates[0].PrivateKey.(ed25519.PrivateKey)
	identity.Destroy()
	identity.Destroy()
	if identity.TLSConfig != nil || config.Certificates[0].PrivateKey != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("Destroy retained the parsed server key")
	}
	if err := ValidateGatewayIdentityBundle(fixtureBundle(f), "https://gateway.example/tunnel"); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayServerSecretRejectsClosedDocumentViolations(t *testing.T) {
	f := testcredentials.New(t)
	valid := f.Payloads["gateway-server"]
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"empty", func([]byte) []byte { return nil }},
		{"oversized", func([]byte) []byte { return bytes.Repeat([]byte(" "), credentialChannelBytes+1) }},
		{"duplicate", func(b []byte) []byte { return insertJSONMember(b, `"format_version":1`) }},
		{"nested duplicate", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"controller_a":`), []byte(`"controller_a":"duplicate","controller_a":`), 1)
		}},
		{"unknown", func(b []byte) []byte { return insertJSONMember(b, `"sandbox_id":"forbidden"`) }},
		{"trailing", func(b []byte) []byte { return append(append([]byte(nil), b...), []byte(`{}`)...) }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"invalid UTF8", func(b []byte) []byte { return append([]byte{0xff}, b...) }},
		{"invalid surrogate", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`spiffe://gateway/controller_a`), []byte(`\uD800`), 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity, err := BuildGatewayServerIdentity("https://gateway.example/tunnel", tc.mutate(valid), f.Payloads["gateway-trust"])
			if identity != nil || !errors.Is(err, ErrGatewayServerDocument) {
				t.Fatalf("invalid secret result: %v", err)
			}
		})
	}
	for _, field := range []string{"format_version", "credential_type", "certificate_chain_pem", "private_key_pem", "client_ca_certificates_pem", "controller_subjects"} {
		for _, missing := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "/null", true: "/missing"}[missing], func(t *testing.T) {
				var document map[string]any
				if err := json.Unmarshal(valid, &document); err != nil {
					t.Fatal(err)
				}
				if missing {
					delete(document, field)
				} else {
					document[field] = nil
				}
				if _, err := decodeGatewayServerCredential(testcredentials.JSON(t, document)); !errors.Is(err, ErrGatewayServerDocument) {
					t.Fatal("missing/null field accepted")
				}
			})
		}
	}
	for _, subjects := range []map[string]any{
		{"controller_a": "spiffe://a"},
		{"controller_a": nil, "controller_b": "spiffe://b"},
		{"controller_a": "spiffe://same", "controller_b": "spiffe://same"},
		{"controller_a": "relative", "controller_b": "spiffe://b"},
		{"controller_a": "spiffe://a#fragment", "controller_b": "spiffe://b"},
		{"controller_a": "spiffe://a", "controller_b": "spiffe://b", "tenant_id": "forbidden"},
	} {
		var document map[string]any
		_ = json.Unmarshal(valid, &document)
		document["controller_subjects"] = subjects
		if _, err := decodeGatewayServerCredential(testcredentials.JSON(t, document)); !errors.Is(err, ErrGatewayServerDocument) {
			t.Fatal("invalid subject pins accepted")
		}
	}
}

func TestGatewayServerIdentityRejectsCertificateViolations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"wrong DNS", func(c *x509.Certificate) { c.DNSNames = []string{"wrong.example"} }},
		{"wildcard", func(c *x509.Certificate) { c.DNSNames = []string{"*.example"} }},
		{"multiple names", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example") }},
		{"extra URI", func(c *x509.Certificate) { u, _ := url.Parse("spiffe://server"); c.URIs = []*url.URL{u} }},
		{"extra email", func(c *x509.Certificate) { c.EmailAddresses = []string{"test@example.test"} }},
		{"CN fallback", func(c *x509.Certificate) { c.DNSNames = nil; c.Subject.CommonName = "gateway.example" }},
		{"client only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"dual usage", func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) }},
		{"any usage", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{"no EKU", func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"unknown EKU", func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} }},
		{"CA leaf", func(c *x509.Certificate) { c.IsCA = true }},
		{"no digital signature", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{"unknown extra SAN", func(c *x509.Certificate) {
			// A second GeneralName unrepresented by the normal DNS/IP/URI fields.
			value, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("gateway.example")}, {Class: 2, Tag: 8, Bytes: []byte{42, 3}}})
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testcredentials.New(t)
			tc.change(f.ServerTemplate)
			certificate, key := testcredentials.Issue(t, f.ServerCA, f.ServerCAKey, f.ServerTemplate, f.ServerKey)
			document := serverDocument(t, f)
			document.CertificateChainPEM, document.PrivateKeyPEM = certificate, key
			identity, err := BuildGatewayServerIdentity("https://gateway.example/tunnel", testcredentials.JSON(t, document), f.Payloads["gateway-trust"])
			if identity != nil || !errors.Is(err, ErrGatewayServerIdentity) {
				t.Fatalf("invalid server certificate accepted: %v", err)
			}
		})
	}
}

func TestGatewayServerIdentityAcceptsIPAndIntermediateChain(t *testing.T) {
	f := testcredentials.New(t)
	intermediateKey := testcredentials.Key(t)
	intermediateTemplate := testcredentials.Template()
	intermediateTemplate.IsCA = true
	intermediateTemplate.KeyUsage = x509.KeyUsageCertSign
	intermediateTemplate.ExtKeyUsage = nil
	intermediateTemplate.NotAfter = time.Now().Add(30 * time.Minute)
	intermediatePEM, _ := testcredentials.Issue(t, f.ServerCA, f.ServerCAKey, intermediateTemplate, intermediateKey)
	block, _ := pem.Decode([]byte(intermediatePEM))
	intermediate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	f.ServerTemplate.DNSNames = nil
	f.ServerTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	certificate, key := testcredentials.Issue(t, intermediate, intermediateKey, f.ServerTemplate, f.ServerKey)
	document := serverDocument(t, f)
	document.CertificateChainPEM, document.PrivateKeyPEM = certificate+intermediatePEM, key
	identity, err := BuildGatewayServerIdentity("https://127.0.0.1:8443/tunnel", testcredentials.JSON(t, document), f.Payloads["gateway-trust"])
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Destroy()
	if len(identity.TLSConfig.Certificates[0].Certificate) != 2 || !identity.ExpiresAt.Equal(intermediate.NotAfter) {
		t.Fatal("intermediate/expiry binding failed")
	}
}

func TestGatewayServerIdentityRejectsUnsupportedKeyAlgorithmAndExpiredRoot(t *testing.T) {
	f := testcredentials.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, f.ServerTemplate, f.ServerCA, &key.PublicKey, f.ServerCAKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	d := serverDocument(t, f)
	d.CertificateChainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	d.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if _, err := BuildGatewayServerIdentity("https://gateway.example/tunnel", testcredentials.JSON(t, d), f.Payloads["gateway-trust"]); !errors.Is(err, ErrGatewayServerIdentity) {
		t.Fatal("non-Ed25519 server identity accepted")
	}
	rootTemplate := *f.ServerCA
	rootTemplate.NotAfter = time.Now().Add(-time.Second)
	rootPEM, _ := testcredentials.Issue(t, &rootTemplate, f.ServerCAKey, &rootTemplate, f.ServerCAKey)
	if _, err := BuildGatewayServerIdentity("https://gateway.example/tunnel", f.Payloads["gateway-server"], []byte(rootPEM)); !errors.Is(err, ErrGatewayServerIdentity) {
		t.Fatal("expired server root accepted")
	}
}

func TestGatewayServerIdentityRejectsPEMTrustAndKeySubstitution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *testcredentials.Fixture, *GatewayServerCredentialDocument)
	}{
		{"key mismatch", func(t *testing.T, f *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			_, d.PrivateKeyPEM = testcredentials.Issue(t, f.ServerCA, f.ServerCAKey, f.ServerTemplate, testcredentials.Key(t))
		}},
		{"CA key reused", func(t *testing.T, f *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.CertificateChainPEM, d.PrivateKeyPEM = testcredentials.Issue(t, f.ServerCA, f.ServerCAKey, f.ServerTemplate, f.ServerCAKey)
		}},
		{"key prefix", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.PrivateKeyPEM = "skipped text\n" + d.PrivateKeyPEM
		}},
		{"key suffix", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.PrivateKeyPEM += "trailing junk"
		}},
		{"two keys", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.PrivateKeyPEM += d.PrivateKeyPEM
		}},
		{"key headers", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			b, _ := pem.Decode([]byte(d.PrivateKeyPEM))
			b.Headers = map[string]string{"Comment": "forbidden"}
			d.PrivateKeyPEM = string(pem.EncodeToMemory(b))
		}},
		{"cert prefix", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.CertificateChainPEM = "skipped text\n" + d.CertificateChainPEM
		}},
		{"malformed PEM before valid PEM", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.CertificateChainPEM = "-----BEGIN CERTIFICATE-----\ninvalid\n" + d.CertificateChainPEM
		}},
		{"cert suffix", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.CertificateChainPEM += "trailing junk"
		}},
		{"duplicate cert", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.CertificateChainPEM += d.CertificateChainPEM
		}},
		{"unrelated chain cert", func(_ *testing.T, f *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.CertificateChainPEM += testcredentials.CertificatePEM(f.ClientCA)
		}},
		{"wrong server root", func(_ *testing.T, f *testcredentials.Fixture, _ *GatewayServerCredentialDocument) {
			f.Payloads["gateway-trust"] = []byte(testcredentials.CertificatePEM(f.ClientCA))
		}},
		{"server leaf as root", func(_ *testing.T, f *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			f.Payloads["gateway-trust"] = []byte(d.CertificateChainPEM)
		}},
		{"private key in trust", func(_ *testing.T, f *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			f.Payloads["gateway-trust"] = []byte(d.PrivateKeyPEM)
		}},
		{"oversized trust", func(_ *testing.T, f *testcredentials.Fixture, _ *GatewayServerCredentialDocument) {
			f.Payloads["gateway-trust"] = bytes.Repeat([]byte(" "), trustChannelBytes+1)
		}},
		{"leaf in client roots", func(_ *testing.T, _ *testcredentials.Fixture, d *GatewayServerCredentialDocument) {
			d.ClientCACertificatesPEM = d.CertificateChainPEM
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testcredentials.New(t)
			d := serverDocument(t, f)
			tc.change(t, f, &d)
			identity, err := BuildGatewayServerIdentity("https://gateway.example/tunnel", testcredentials.JSON(t, d), f.Payloads["gateway-trust"])
			if identity != nil || !errors.Is(err, ErrGatewayServerIdentity) {
				t.Fatalf("invalid PEM/key/trust accepted: %v", err)
			}
		})
	}
}

func TestGatewayIdentityBundleRejectsCrossActorAndKeyReuse(t *testing.T) {
	for _, kind := range []string{"subject swap", "wrong client root", "client key reuse", "Provider key reuse", "Admission key reuse", "missing client", "malformed Provider"} {
		t.Run(kind, func(t *testing.T) {
			f := testcredentials.New(t)
			switch kind {
			case "subject swap":
				d := serverDocument(t, f)
				d.ControllerSubjects.ControllerA, d.ControllerSubjects.ControllerB = d.ControllerSubjects.ControllerB, d.ControllerSubjects.ControllerA
				f.Payloads["gateway-server"] = testcredentials.JSON(t, d)
			case "wrong client root":
				d := serverDocument(t, f)
				d.ClientCACertificatesPEM = testcredentials.CertificatePEM(f.ServerCA)
				f.Payloads["gateway-server"] = testcredentials.JSON(t, d)
			case "client key reuse":
				var d GatewayCredentialDocument
				_ = json.Unmarshal(f.Payloads["gateway-controller-a"], &d)
				leaf := testcredentials.Template()
				u, _ := url.Parse(d.ControllerSubject)
				leaf.URIs = []*url.URL{u}
				d.CertificateChainPEM, d.PrivateKeyPEM = testcredentials.Issue(t, f.ClientCA, f.ClientCAKey, leaf, f.ServerKey)
				f.Payloads["gateway-controller-a"] = testcredentials.JSON(t, d)
			case "Provider key reuse":
				var d ProviderCredentialDocument
				_ = json.Unmarshal(f.Payloads["provider-controller-a"], &d)
				leaf := testcredentials.Template()
				u, _ := url.Parse(d.ControllerSubject)
				leaf.URIs = []*url.URL{u}
				d.CertificateChainPEM, d.PrivateKeyPEM = testcredentials.Issue(t, f.ClientCA, f.ClientCAKey, leaf, f.ServerKey)
				f.Payloads["provider-controller-a"] = testcredentials.JSON(t, d)
			case "Admission key reuse":
				var d ProviderCredentialDocument
				_ = json.Unmarshal(f.Payloads["provider-controller-a"], &d)
				d.Admission.Ed25519PrivateKey = base64.RawURLEncoding.EncodeToString(f.ServerKey)
				f.Payloads["provider-controller-a"] = testcredentials.JSON(t, d)
			case "missing client":
				delete(f.Payloads, "gateway-controller-b")
			case "malformed Provider":
				f.Payloads["provider-controller-b"] = []byte("invalid")
			}
			if err := ValidateGatewayIdentityBundle(fixtureBundle(f), "https://gateway.example/tunnel"); !errors.Is(err, ErrGatewayIdentityBinding) {
				t.Fatalf("invalid binding accepted: %v", err)
			}
		})
	}
}

func serverDocument(t testing.TB, f *testcredentials.Fixture) GatewayServerCredentialDocument {
	t.Helper()
	var d GatewayServerCredentialDocument
	if err := json.Unmarshal(f.Payloads["gateway-server"], &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func fixtureBundle(f *testcredentials.Fixture) *Bundle {
	b := &Bundle{payloads: f.Payloads}
	for _, p := range f.Payloads {
		b.total += len(p)
	}
	return b
}
