#!/bin/sh
# Wrapper invoked from ClusterFuzzLite bundles to launch llvm-symbolizer with the
# copied dynamic loader and libraries.
export LC_ALL=C
set -eu
DIR=$(cd -- "$(dirname -- "$0")" && pwd)
LOADER="$DIR/__CFL_LOADER__"
REAL="$DIR/__CFL_SYMBOLIZER_REAL__"
echo "[cfl] llvm-symbolizer wrapper launching '$REAL' via loader '$LOADER'" >&2
exec "$LOADER" --library-path "$DIR" "$REAL" "$@"
