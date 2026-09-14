# Repository Guidelines

Read `README.md` and `docs/STATUS.md` before changing behavior.

This repository is an external-caller candidate for the repository-owned
`sandbox-runtime` Provider Contract. Keep these boundaries strict:

- consume only the public Contract, qualification profile, and adapter
  protocol authorities pinned by `authority.lock.json`;
- do not import `github.com/shell-echo/sandbox-runtime` implementation,
  internal, command, test-helper, or `e2e` packages;
- generated code derived solely from the locked public Contract is permitted;
- keep Provider wire DTOs local to this repository and separate from caller
  business policy;
- reject unknown or oversized input, preserve deadlines and cancellation, and
  never retain credentials or private correlation material in evidence;
- do not claim external provenance, interoperability, or qualification from a
  local build or repository-owned fixture.

Format Go changes with `gofmt`, then run:

```bash
mise exec -- go test -race -shuffle=on -count=1 ./...
mise exec -- go vet ./...
mise exec -- go run ./cmd/verify-authority \
  -provider-source-root ../sandbox-runtime
```

A commit, push, hosted build, external ownership attestation, qualification
run, and evidence publication each require separate authorization.
