# Candidate release artifacts

e1.8a defines one content-addressed local candidate bundle. It is designed so
an independent builder can reproduce and observe the exact inputs and outputs;
the local bundle is not itself an independent build or source-hosting
attestation.

## Build

Run the builder through the pinned mise toolchain and supply a new output
directory:

```bash
mise exec -- go run ./cmd/release-artifacts \
  -source-root "$PWD" \
  -output "$PWD/dist/e1.8a-darwin-arm64" \
  -goos darwin \
  -goarch arm64
```

The builder refuses an existing output directory. It obtains the exact tracked
and non-ignored untracked source inventory from Git, rejects non-regular and
unsafe paths, and writes a deterministic uncompressed `source.tar` with
normalized ownership, modes and timestamps. Its SHA-256 becomes a 64-hex
`source-revision` embedded into the qualification adapter as both the Caller
and Adapter release identity. The same identity is retained for the Caller
Gateway artifact in the bundle manifest.

The archive is extracted into two distinct temporary roots. Each root builds
the three command artifacts with the exact argument and environment arrays
recorded in `release-manifest.json`. Builds require `-mod=readonly`,
`-trimpath`, `-buildvcs=false`, an empty Go build ID, `CGO_ENABLED=0`, an
explicit target and architecture baseline, `GOWORK=off`, `GOENV=off`, and the
recorded source-identity linker values. The bundle is published only if every
corresponding executable is byte-identical across both runs.

The output is:

```text
release-manifest.json
source.tar
artifacts/qualification-adapter
artifacts/external-caller
artifacts/caller-gateway
```

The canonical RFC 8785 manifest records the source archive digest and size,
Git commit/tree plus dirty state, optional source repository, authority-lock
digest, Go version and raw Go executable digest, exact command/environment
arrays, all three raw executable digests and sizes, and the shared immutable
source identity. Its own digest excludes only `manifest_digest` under the
declared profile.

Verify retained bytes without rebuilding:

```bash
mise exec -- go run ./cmd/release-artifacts \
  -verify "$PWD/dist/e1.8a-darwin-arm64"
```

Verification requires exact canonical bytes, recomputes the manifest digest,
checks the deterministic archive shape/count/digest, checks every executable
digest/size/mode, and rejects unknown fields, unsafe paths or changed command
authority.

## Provenance boundary

The manifest deliberately records:

- `evidence_kind: candidate-local-reproducibility-only`;
- no independent build attestation;
- no independent source-hosting attestation;
- no qualification process-supervisor observation; and
- `qualification_eligible: false`.

The implementation began as an uncommitted worktree without a source remote, so
its local bundle alone remains an exact content-addressed candidate snapshot,
not proof of external ownership. A private source boundary now exists at
`shell-echo/sandbox-runtime-external-caller`, together with the hosted workflow
below. Completing e1.8a still requires pushing the exact source revision and a
successful independent build/attestation whose observed artifact digests match
this format. The operator must then supply those facts through the locked
artifact-observation boundary. The candidate must not change the local manifest
flags to manufacture that evidence.

The repository also defines
`.github/workflows/release-provenance.yml`. It uses commit-pinned checkout,
Go-setup, artifact-upload and GitHub build-provenance actions on an Ubuntu 24.04
hosted runner. The workflow reruns the complete race/shuffle suite and vet,
serializing test packages because several suites compile and supervise real
child executables on the bounded runner. It then builds and verifies a
`linux/amd64` bundle, checks public authority snapshot
`96ee9933fe2a3bcfaef291b486cd6b8f7095539a` (which retains Provider Contract
revision `22ba6987ea5fbc37d53942720133c0acad199edd`), uploads the
bundle without compression, and requests one GitHub/Sigstore attestation over
the source archive, manifest and all three executables. A successful run and
subsequent `gh attestation verify` are required before the external provenance
gate can be closed; workflow definition alone is not evidence.

Private hosted run `35067554697` proves the workflow through source verification,
bundle build/verification, locked-authority verification and artifact upload for
source `32bfb5fd786228769742cd90db9cb18f127edf6f`. Its downloaded artifact also
passes this tool's strict verifier. The attestation action then failed closed
because GitHub does not offer attestations for user-owned private repositories.
That partial run is hosted-build evidence, not an attestation and not completion
of e1.8a.
