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
its local bundle alone was only an exact content-addressed candidate snapshot.
The source repository is now public and the hosted workflow below supplies the
external build/attestation observations. The candidate manifest deliberately
retains its conservative flags; external evidence is not manufactured by
changing candidate-controlled bytes.

The repository also defines
`.github/workflows/release-provenance.yml`. It uses commit-pinned checkout,
Go-setup, artifact-upload and GitHub build-provenance actions on an Ubuntu 24.04
hosted runner. The workflow reruns the complete race/shuffle suite and vet,
serializing test packages because several suites compile and supervise real
child executables on the bounded runner. It then builds and verifies a
`linux/amd64` bundle, checks public authority snapshot
`66dc11f11584df2c15804ee10a3bfcd0294600b0` (which retains Provider Contract
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

After explicit public-visibility authorization, hosted run `35068957048`
completed every step for source `58a211f0c167af3ec117c8cb8247bfe268bbae40`.
It uploaded artifact `10435915145`, created Public Good Sigstore/Rekor
attestation `47846951` over the source archive, manifest and three executables,
and published the immutable references. The downloaded bundle passed `-verify`,
and all five subjects separately passed `gh attestation verify`. Those external
observations close e1.8a; they do not establish the later supervisor/runtime
qualification evidence.

The image-pinned successor candidate at merge
`6d18ce3d091ec7da141565d1c93ebfab0eeb55fa` was rebuilt by hosted run
`35175318990`. Artifact `10477793808` has archive digest
`sha256:64df25eb47810e170525e11455602127d16b5b80f8d3a51f7ad0ebeff00c6a5d`;
its downloaded bundle passed strict verification with manifest self-digest
`sha256:6f1d07d26001e939d34a37d28a774dc281627d61f65228e5c92d3ab690625013`.
Attestation `48082145` covers the source archive, raw manifest and three
executables. All five downloaded subjects independently passed
`gh attestation verify`, which bound the exact public repository, `main` ref,
source/workflow SHA, GitHub-hosted runner, workflow-dispatch trigger, SLSA
predicate, run attempt and Rekor timestamp. This refresh makes the exact
image-pinned artifact available to the e1.8b supervisor; it is not itself a
live-runtime or qualification result.

The subsequent documentation-only evidence commit is outside that retained
bundle and does not change its `6d18ce3d...` source identity.
