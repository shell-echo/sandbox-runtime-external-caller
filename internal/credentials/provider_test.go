package credentials

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuildProviderAccessBindsMTLSSubjectTrustAndAdmissionSigner(t *testing.T) {
	payload, trust, admissionPublicKey := testProviderCredential(t, "controller_a", "spiffe://provider/controller-a", clientLeafOptions{})
	access, err := BuildProviderAccess("https://provider.example:8443", "controller_a", payload, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	if access.Actor != "controller_a" || access.ControllerSubject != "spiffe://provider/controller-a" || access.Client == nil || access.Transport == nil || access.Admission == nil {
		t.Fatalf("ProviderAccess = %#v", access)
	}
	config := access.Transport.TLSClientConfig
	if access.Transport.Proxy != nil || config == nil || config.MinVersion != tls.VersionTLS12 || config.ServerName != "provider.example" || config.RootCAs == nil || len(config.Certificates) != 1 {
		t.Fatalf("mTLS transport is incomplete: %#v", access.Transport)
	}
	signature, err := access.Admission.Signer.Sign([]byte("candidate-owned-input"))
	if err != nil || !ed25519.Verify(admissionPublicKey, []byte("candidate-owned-input"), signature) {
		t.Fatalf("admission signature verification failed: %v", err)
	}
	authority, ok := access.AdmissionAuthority("provider-revision-1")
	if !ok || authority.ControllerSubject != access.ControllerSubject || authority.ProviderRevisionID != "provider-revision-1" || authority.Issuer != "https://caller.example.test/control" {
		t.Fatalf("admission authority = %#v, %v", authority, ok)
	}
}

func TestBuildProviderAccessAllowsUnadmittedMTLSIdentityWithoutBearerKey(t *testing.T) {
	payload, trust, _ := testProviderCredential(t, "same_ca_unadmitted", "spiffe://provider/unadmitted", clientLeafOptions{withoutAdmission: true})
	access, err := BuildProviderAccess("https://127.0.0.1:8443", "same_ca_unadmitted", payload, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	if access.Admission != nil {
		t.Fatal("same-CA unadmitted identity unexpectedly has bearer signing material")
	}
	if _, ok := access.AdmissionAuthority("provider-revision-1"); ok {
		t.Fatal("same-CA unadmitted identity produced protected-admission authority")
	}
}

func TestProviderAccessCloseClearsOwnedSigningAndTLSReferences(t *testing.T) {
	payload, trust, _ := testProviderCredential(t, "controller_a", "spiffe://provider/controller-a", clientLeafOptions{})
	access, err := BuildProviderAccess("https://provider.example", "controller_a", payload, trust)
	if err != nil {
		t.Fatal(err)
	}
	signer := access.Admission.Signer
	tlsConfig := access.Transport.TLSClientConfig
	if len(tlsConfig.Certificates) != 1 || tlsConfig.Certificates[0].PrivateKey == nil {
		t.Fatal("test Provider access has no TLS private key")
	}
	access.Close()
	access.Close()
	if access.Actor != "" || access.ControllerSubject != "" || access.Admission != nil || access.Client != nil || access.Transport != nil {
		t.Fatalf("closed Provider access retained public references: %#v", access)
	}
	if tlsConfig.RootCAs != nil || len(tlsConfig.Certificates) != 0 {
		t.Fatalf("closed TLS config retained credentials: %#v", tlsConfig)
	}
	if _, err := signer.Sign([]byte("must-fail-after-close")); err == nil || signer.KeyID() != "" {
		t.Fatalf("closed admission signer remained usable: %v", err)
	}
}

func TestBuildProviderAccessFromBundleSelectsExactActorChannel(t *testing.T) {
	controllerA, trust, _ := testProviderCredential(t, "controller_a", "spiffe://provider/controller-a", clientLeafOptions{})
	controllerB, _, _ := testProviderCredential(t, "controller_b", "spiffe://provider/controller-b", clientLeafOptions{})
	bundle := &Bundle{payloads: map[string][]byte{
		"provider-controller-a": controllerA,
		"provider-controller-b": controllerB,
		"provider-trust":        trust,
	}, total: len(controllerA) + len(controllerB) + len(trust)}
	defer bundle.Destroy()
	access, err := BuildProviderAccessFromBundle(bundle, "https://provider.example", "controller_a")
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	if access.Actor != "controller_a" || access.ControllerSubject != "spiffe://provider/controller-a" {
		t.Fatalf("selected access = %#v", access)
	}
	if _, err := BuildProviderAccessFromBundle(bundle, "https://provider.example", "unknown"); !errors.Is(err, ErrCredentialDocument) {
		t.Fatalf("unknown actor error = %v", err)
	}
}

func TestBuildProviderAccessRejectsClosedDocumentAndIdentityViolations(t *testing.T) {
	valid, trust, _ := testProviderCredential(t, "controller_a", "spiffe://provider/controller-a", clientLeafOptions{})

	tests := []struct {
		name    string
		origin  string
		actor   string
		payload []byte
		trust   []byte
		want    error
	}{
		{name: "actor mismatch", origin: "https://provider.example", actor: "controller_b", payload: valid, trust: trust, want: ErrCredentialDocument},
		{name: "unknown member", origin: "https://provider.example", actor: "controller_a", payload: insertJSONMember(valid, `"sandbox_id":"reinjected"`), trust: trust, want: ErrCredentialDocument},
		{name: "duplicate member", origin: "https://provider.example", actor: "controller_a", payload: insertJSONMember(valid, `"actor":"controller_a"`), trust: trust, want: ErrCredentialDocument},
		{name: "invalid origin", origin: "https://provider.example/path", actor: "controller_a", payload: valid, trust: trust, want: nil},
		{name: "invalid trust", origin: "https://provider.example", actor: "controller_a", payload: valid, trust: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not allowed")}), want: ErrTrustBundle},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access, err := BuildProviderAccess(test.origin, test.actor, test.payload, test.trust)
			if access != nil {
				access.Close()
			}
			if test.name == "invalid origin" {
				if err == nil {
					t.Fatal("invalid origin was accepted")
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("BuildProviderAccess() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestBuildProviderAccessRejectsCertificateAndAdmissionViolations(t *testing.T) {
	tests := []struct {
		name    string
		actor   string
		subject string
		options clientLeafOptions
		mutate  func([]byte) []byte
		want    error
	}{
		{name: "declared subject mismatch", actor: "controller_a", subject: "spiffe://provider/controller-a", options: clientLeafOptions{certificateSubject: "spiffe://provider/other"}, want: ErrClientCertificate},
		{name: "multiple URI SANs", actor: "controller_a", subject: "spiffe://provider/controller-a", options: clientLeafOptions{extraSubject: "spiffe://provider/extra"}, want: ErrClientCertificate},
		{name: "server auth only", actor: "controller_a", subject: "spiffe://provider/controller-a", options: clientLeafOptions{serverAuthOnly: true}, want: ErrClientCertificate},
		{name: "expired leaf", actor: "controller_a", subject: "spiffe://provider/controller-a", options: clientLeafOptions{expired: true}, want: ErrClientCertificate},
		{name: "admitted missing admission", actor: "controller_a", subject: "spiffe://provider/controller-a", options: clientLeafOptions{withoutAdmission: true}, want: ErrCredentialDocument},
		{name: "unadmitted omitted admission member", actor: "same_ca_unadmitted", subject: "spiffe://provider/unadmitted", options: clientLeafOptions{withoutAdmission: true}, mutate: func(payload []byte) []byte {
			return []byte(strings.Replace(string(payload), `,"admission":null`, "", 1))
		}, want: ErrCredentialDocument},
		{name: "unadmitted has admission", actor: "same_ca_unadmitted", subject: "spiffe://provider/unadmitted", options: clientLeafOptions{}, want: ErrCredentialDocument},
		{name: "padded admission key", actor: "controller_a", subject: "spiffe://provider/controller-a", options: clientLeafOptions{}, mutate: func(payload []byte) []byte {
			var document ProviderCredentialDocument
			if err := json.Unmarshal(payload, &document); err != nil {
				t.Fatal(err)
			}
			document.Admission.Ed25519PrivateKey += "="
			result, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}, want: ErrAdmissionKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, trust, _ := testProviderCredential(t, test.actor, test.subject, test.options)
			if test.mutate != nil {
				payload = test.mutate(payload)
			}
			access, err := BuildProviderAccess("https://provider.example", test.actor, payload, trust)
			if access != nil {
				access.Close()
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("BuildProviderAccess() error = %v, want %v", err, test.want)
			}
		})
	}
}

type clientLeafOptions struct {
	certificateSubject string
	extraSubject       string
	serverAuthOnly     bool
	expired            bool
	withoutAdmission   bool
}

func testProviderCredential(t *testing.T, actor, declaredSubject string, options clientLeafOptions) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "candidate test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateSubject := options.certificateSubject
	if certificateSubject == "" {
		certificateSubject = declaredSubject
	}
	primaryURI, err := url.Parse(certificateSubject)
	if err != nil {
		t.Fatal(err)
	}
	uris := []*url.URL{primaryURI}
	if options.extraSubject != "" {
		extraURI, err := url.Parse(options.extraSubject)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, extraURI)
	}
	notBefore, notAfter := now.Add(-time.Hour), now.Add(time.Hour)
	if options.expired {
		notBefore, notAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	extendedUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if options.serverAuthOnly {
		extendedUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "candidate test client"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: extendedUsage, URIs: uris,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	credential := ProviderCredentialDocument{
		FormatVersion: 1, CredentialType: ProviderCredentialType, Actor: actor, ControllerSubject: declaredSubject,
		CertificateChainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		PrivateKeyPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})),
	}
	var admissionPublicKey ed25519.PublicKey
	if !options.withoutAdmission {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		admissionPublicKey = publicKey
		credential.Admission = &ProviderAdmissionSecret{
			Issuer: "https://caller.example.test/control", ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:provider-1",
			KeyID: "caller-key-1", Ed25519PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
		}
	}
	payload, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return payload, trust, admissionPublicKey
}

func insertJSONMember(document []byte, member string) []byte {
	return []byte("{" + member + "," + strings.TrimPrefix(string(document), "{"))
}
