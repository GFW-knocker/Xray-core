#!/usr/bin/env bash
#
# Regenerate the MVLESS protocol from VLESS.
#
# MVLESS is VLESS with a different protocol version byte. Nothing else about it
# may differ, so it is not maintained by hand: this script re-derives the whole
# proxy/mvless tree (plus the JSON config and the tests) from the VLESS sources
# by mechanical renaming, and patches the one line that is allowed to differ.
#
# Everything below is a pure function of proxy/vless, infra/conf/vless*.go,
# testing/scenarios/vless_test.go and $MVLESS_VERSION_BYTE. The only place a
# semantic difference is introduced is the "applying the version byte" step --
# that single sed is the entire delta between the two protocols.
#
# Run it after every sync with upstream VLESS:
#
#     bash infra/mvlessgen/sync-mvless.sh
#     bash infra/mvlessgen/verify-mvless.sh
#
# Usage:
#     sync-mvless.sh              regenerate in place
#     sync-mvless.sh --out DIR    write the generated files under DIR instead,
#                                 leaving the working tree untouched
#                                 (used by verify-mvless.sh)
#
# Requirements: protoc and protoc-gen-go matching the versions the rest of the
# repo's *.pb.go files were generated with, on PATH or via $PROTOC and
# $PROTOC_GEN_GO.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# The single permitted difference between VLESS and MVLESS.
MVLESS_VERSION_BYTE=150

EXE=""
[ "$(go env GOOS)" = "windows" ] && EXE=".exe"
PROTOC="${PROTOC:-protoc$EXE}"
PROTOC_GEN_GO="${PROTOC_GEN_GO:-$(go env GOPATH)/bin/protoc-gen-go$EXE}"

OUT=""
while [ $# -gt 0 ]; do
	case "$1" in
	--out)
		OUT="$2"
		shift 2
		;;
	*)
		echo "sync-mvless: unknown argument: $1" >&2
		exit 2
		;;
	esac
done

# Standalone generated files, as vless_source:mvless_output pairs.
PAIRS=(
	"infra/conf/vless.go:infra/conf/mvless.go"
	"infra/conf/vless_test.go:infra/conf/mvless_test.go"
	"testing/scenarios/vless_test.go:testing/scenarios/mvless_test.go"
)

# rename rewrites VLESS identifiers into MVLESS ones on stdin.
#
# Order matters. "Mvless" itself contains the substring "vless", so the
# lowercase rule has to run first or it would rewrite its own output into
# "Mmvless". VlessRoute is restored at the end: it is a field of the shared
# session.Inbound struct, not something MVLESS owns.
rename() {
	sed -e 's/vless/mvless/g' \
	    -e 's/Vless/Mvless/g' \
	    -e 's/VLess/MVLess/g' \
	    -e 's/VLESS/MVLESS/g' \
	    -e 's/MvlessRoute/VlessRoute/g'
}

# match_eol $reference $target gives $target the line endings of $reference.
# proxy/vless is CRLF in this repo while infra/conf is LF, sed here does not
# preserve CR, and gofmt always writes LF -- so this runs last, over everything.
match_eol() {
	if grep -qU $'\r' "$1"; then
		sed -i -e 's/\r$//' -e 's/$/\r/' "$2"
	else
		sed -i -e 's/\r$//' "$2"
	fi
}

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

echo "==> deriving proxy/mvless from proxy/vless"
# *.pb.go is generated from the *.proto files below, so it is not copied.
while IFS= read -r rel; do
	dst="$stage/proxy/mvless/${rel}"
	mkdir -p "$(dirname "$dst")"
	rename <"proxy/vless/${rel}" >"$dst"
done < <(cd proxy/vless && find . -type f ! -name '*.pb.go' | sed 's|^\./||')
mv "$stage/proxy/mvless/vless.go" "$stage/proxy/mvless/mvless.go"

echo "==> deriving infra/conf/mvless.go and the tests"
for pair in "${PAIRS[@]}"; do
	dst="$stage/${pair##*:}"
	mkdir -p "$(dirname "$dst")"
	rename <"${pair%%:*}" >"$dst"
done

echo "==> applying the version byte (${MVLESS_VERSION_BYTE})"
# This is the one and only semantic change. Everything else in this script is
# a rename. If VLESS ever stops matching these two lines, fail loudly rather
# than silently emitting an MVLESS that is wire-identical to VLESS.
enc="$stage/proxy/mvless/encoding/encoding.go"
sites="$(grep -cE $'^\tVersion = byte\\(0\\)\r?$|^\tcase 0:\r?$' "$enc")"
if [ "$sites" -ne 2 ]; then
	echo "sync-mvless: expected 2 version sites in encoding.go, found $sites" >&2
	echo "sync-mvless: VLESS changed shape; update this script." >&2
	exit 1
fi
sed -i -e "s/^\tVersion = byte(0)/\tVersion = byte(${MVLESS_VERSION_BYTE})/" \
       -e "s/^\tcase 0:/\tcase ${MVLESS_VERSION_BYTE}:/" "$enc"

echo "==> restoring wire-critical strings"
# The rename must not touch anything that ends up on the wire or feeds a key
# derivation: the version byte is the only permitted protocol difference, and
# changing a derivation context would additionally break every already-deployed
# MVLESS peer. blake3's context string is the one such literal in VLESS today.
xor="$stage/proxy/mvless/encryption/xor.go"
if ! grep -q 'blake3.DeriveKey(k, "MVLESS", key)' "$xor"; then
	echo "sync-mvless: blake3 derivation context not found in xor.go" >&2
	echo "sync-mvless: VLESS changed shape; update this script." >&2
	exit 1
fi
sed -i 's/blake3.DeriveKey(k, "MVLESS", key)/blake3.DeriveKey(k, "VLESS", key)/' "$xor"

# Catch a future VLESS adding another wire-critical literal: the encryption
# package derives keys and frames records, so no MVLESS-branded string belongs
# in it. Anything that trips this needs a decision, not an automatic rename.
if grep -rn '"[^"]*MVLESS[^"]*"' "$stage/proxy/mvless/encryption/"; then
	echo "sync-mvless: MVLESS string literal in the encryption package (above)." >&2
	echo "sync-mvless: if it is wire-critical, restore it like the blake3 context." >&2
	exit 1
fi

echo "==> generating protobuf"
if ! command -v "$PROTOC" >/dev/null 2>&1 && [ ! -x "$PROTOC" ]; then
	echo "sync-mvless: protoc not found (set \$PROTOC)" >&2
	exit 1
fi
if [ ! -x "$PROTOC_GEN_GO" ] && ! command -v "$PROTOC_GEN_GO" >/dev/null 2>&1; then
	echo "sync-mvless: protoc-gen-go not found (set \$PROTOC_GEN_GO)" >&2
	exit 1
fi
while IFS= read -r rel; do
	"$PROTOC" \
		--proto_path "$stage" \
		--proto_path "$ROOT" \
		--go_out "$stage" \
		--go_opt paths=source_relative \
		--plugin "protoc-gen-go=${PROTOC_GEN_GO}" \
		"$rel"
done < <(cd "$stage" && find proxy/mvless -name '*.proto')

# core/config.pb.go is the repo's reference for the generator toolchain, and CI
# (.github/workflows/test.yml, check-proto) requires every *.pb.go to carry the
# same 4-line header. Fail here rather than committing files that job rejects.
head -n 4 core/config.pb.go | tr -d '\r' >"$stage/.pbref"
while IFS= read -r pb; do
	if ! head -n 4 "$pb" | tr -d '\r' | cmp -s - "$stage/.pbref"; then
		echo "sync-mvless: wrong protobuf toolchain; $(basename "$pb") header is" >&2
		head -n 4 "$pb" | tr -d '\r' | sed 's/^/    /' >&2
		echo "  but core/config.pb.go requires" >&2
		sed 's/^/    /' "$stage/.pbref" >&2
		echo >&2
		echo "  go install google.golang.org/protobuf/cmd/protoc-gen-go@v$(sed -n '3s/.*protoc-gen-go v//p' "$stage/.pbref")" >&2
		echo "  protoc $(sed -n '4s/.*protoc *v5\./ /p' "$stage/.pbref" | tr -d ' ') is required on PATH (or set \$PROTOC)" >&2
		exit 1
	fi
done < <(find "$stage/proxy/mvless" -name '*.pb.go')
rm -f "$stage/.pbref"

echo "==> gofmt"
gofmt -w "$stage/proxy/mvless"
for pair in "${PAIRS[@]}"; do
	gofmt -w "$stage/${pair##*:}"
done

echo "==> matching line endings to the VLESS sources"
while IFS= read -r rel; do
	dst="$stage/proxy/mvless/${rel}"
	[ "$rel" = "vless.go" ] && dst="$stage/proxy/mvless/mvless.go"
	match_eol "proxy/vless/${rel}" "$dst"
done < <(cd proxy/vless && find . -type f | sed 's|^\./||')
for pair in "${PAIRS[@]}"; do
	match_eol "${pair%%:*}" "$stage/${pair##*:}"
done

if [ -n "$OUT" ]; then
	echo "==> writing to $OUT"
	mkdir -p "$OUT"
	cp -r "$stage/." "$OUT/"
else
	echo "==> installing into the working tree"
	rm -rf proxy/mvless
	cp -r "$stage/." "$ROOT/"
fi

echo "==> done"
