# mvlessgen

MVLESS is VLESS with one different byte: the protocol version, `150` instead of
`0`. Everything else — the request header, addons, XTLS Vision, VLESS
Encryption, the JSON config schema — is identical by construction.

**Do not edit `proxy/mvless/`, `infra/conf/mvless.go`, `infra/conf/mvless_test.go`
or `testing/scenarios/mvless_test.go` by hand.** They are generated. Change the
VLESS sources instead, then re-run the generator.

## Usage

```sh
bash infra/mvlessgen/sync-mvless.sh      # regenerate MVLESS from VLESS
bash infra/mvlessgen/verify-mvless.sh    # check MVLESS has not drifted
```

`verify-mvless.sh` runs in CI (`.github/workflows/test.yml`, job `check-mvless`)
and fails the build if the committed MVLESS is not exactly what the generator
produces from the current VLESS sources.

Both need:

- `protoc` and `protoc-gen-go` at the versions named in `core/config.pb.go`'s
  header — on `PATH` or via `$PROTOC` / `$PROTOC_GEN_GO`. `sync-mvless.sh`
  checks the generated headers and tells you the exact versions if they're wrong.
- `gofumpt` at `GOFUMPT_VERSION` (kept in step with
  `.github/workflows/test.yml`) — found in `GOPATH/bin`, on `PATH`, or via
  `$GOFUMPT`. It must be the formatter CI checks with, not plain `gofmt`:
  otherwise the generator could emit files that `check-format` rejects and
  nobody can fix, since hand-formatting a generated file breaks
  `verify-mvless.sh`.

## What the generator does

1. Copies `proxy/vless/**` (minus `*.pb.go`) and the three standalone files,
   renaming `vless`/`Vless`/`VLess`/`VLESS` to their `m`-prefixed forms.
   `VlessRoute` is exempt: it is a field of the shared `session.Inbound`.
2. Restores wire-critical strings that must *not* be renamed — currently the
   blake3 key-derivation context in `encryption/xor.go`. Renaming it would make
   MVLESS derive different keys than VLESS *and* break already-deployed peers.
   A guard fails the build if a new `"MVLESS"` literal shows up in the
   encryption package, so a future VLESS change cannot slip one through.
3. Applies the one permitted semantic change: `Version = byte(150)`.
4. Regenerates `*.pb.go` with protoc and checks the headers match the repo's.
5. Runs `gofumpt`, then restores each file's line endings to match its VLESS
   source (`proxy/vless` is CRLF here, `infra/conf` is LF).

## Adding a wire-critical string

If VLESS gains another literal that must stay byte-identical in MVLESS — a
derivation context, a protocol label, a magic string — add a restore step next
to the blake3 one in `sync-mvless.sh`. Log messages, error text, panics and
`session.Inbound.Name` are *not* wire-critical and should keep the MVLESS name.

## Names that leak outside the generated tree

MVLESS reports itself as `mvless` / `mvless-reverse` in `session.Inbound.Name`.
`proxy/freedom` switches on that name to pick default final rules, so both
names are listed there alongside the VLESS ones. If a new consumer of
`Inbound.Name` special-cases `vless`, it must special-case `mvless` too.
