#!/usr/bin/env bash
# Builds "toxpeer", a tiny c-toxcore client used by the interop tests (Tests/Interop).
# Requires git, a C compiler and libsodium (brew install libsodium / apt install libsodium-dev).
#
#   scripts/build-toxpeer.sh [output-dir]
#   export TOXIDE_TOXPEER=<output-dir>/toxpeer
#   dotnet test
#
# TOXCORE_REF selects the c-toxcore tag (default: the latest release tested with Toxide).
# Extra compiler flags go in CFLAGS (e.g. CFLAGS="-isysroot <sdk>" on macOS with a mismatched SDK).
set -euo pipefail

TOXCORE_REF="${TOXCORE_REF:-v0.2.23}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/.toxpeer}"
CC="${CC:-cc}"
CFLAGS="${CFLAGS:-}"

mkdir -p "$OUT"
cd "$OUT"

if [ ! -d c-toxcore ]; then
  git clone --quiet --depth 1 --branch "$TOXCORE_REF" --recurse-submodules --shallow-submodules \
    https://github.com/TokTok/c-toxcore.git
fi

if pkg-config --exists libsodium 2>/dev/null; then
  SODIUM_CFLAGS="$(pkg-config --cflags libsodium)"
  SODIUM_LIBS="$(pkg-config --libs libsodium)"
elif command -v brew >/dev/null 2>&1; then
  SODIUM_CFLAGS="-I$(brew --prefix libsodium)/include"
  SODIUM_LIBS="-L$(brew --prefix libsodium)/lib -lsodium"
else
  SODIUM_CFLAGS=""
  SODIUM_LIBS="-lsodium"
fi

case "$(uname -s)" in
  Darwin) PLATFORM_FLAGS="-D_DARWIN_C_SOURCE" ;;
  *) PLATFORM_FLAGS="-D_GNU_SOURCE" ;;
esac

mkdir -p obj
SOURCES=$(ls c-toxcore/toxcore/*.c c-toxcore/toxcore/events/*.c 2>/dev/null | grep -v -E '_test|_fuzz|_bench' || true)
SOURCES="$SOURCES c-toxcore/toxencryptsave/toxencryptsave.c $(ls c-toxcore/third_party/cmp/cmp.c 2>/dev/null || true)"

for src in $SOURCES; do
  obj="obj/$(echo "$src" | tr / _).o"
  if [ ! -f "$obj" ]; then
    # shellcheck disable=SC2086
    "$CC" -O1 -w -std=c11 $PLATFORM_FLAGS $CFLAGS $SODIUM_CFLAGS -Ic-toxcore -Ic-toxcore/third_party -c "$src" -o "$obj"
  fi
done

# shellcheck disable=SC2086
"$CC" -O1 -w $PLATFORM_FLAGS $CFLAGS $SODIUM_CFLAGS -Ic-toxcore "$ROOT/Tests/Interop/toxpeer.c" obj/*.o $SODIUM_LIBS -lpthread -lm -o toxpeer

echo "Built $OUT/toxpeer (c-toxcore $TOXCORE_REF)"
echo "export TOXIDE_TOXPEER=$OUT/toxpeer"
