# shellcheck shell=bash

export LC_ALL=C

SYMBOLIZER_DEPENDENCIES=()
SYMBOLIZER_LDD_MISSING=0

ensure_symbolizer_available() {
  if ls "$EXPECTED_SYMBOLIZER" >/dev/null 2>&1; then
    echo "llvm-symbolizer found at $EXPECTED_SYMBOLIZER" >&2
    return 0
  fi

  local actual_symbolizer
  actual_symbolizer="$(command -v llvm-symbolizer || true)"
  if [ -n "$actual_symbolizer" ]; then
    echo "llvm-symbolizer found at $actual_symbolizer instead of $EXPECTED_SYMBOLIZER" >&2
  else
    echo "llvm-symbolizer not found (expected at $EXPECTED_SYMBOLIZER)" >&2
  fi
  exit 1
}

enumerate_symbolizer_dependencies() {
  local binary="$1"

  SYMBOLIZER_DEPENDENCIES=()
  SYMBOLIZER_LDD_MISSING=0

  if [ ! -x "$binary" ]; then
    return 0
  fi

  if ! command -v ldd >/dev/null 2>&1; then
    echo "ldd not available; skipping dependency enumeration for $binary" >&2
    return 1
  fi

  while IFS= read -r line; do
    local leading
    leading="${line%%[![:space:]]*}"
    line="${line#"$leading"}"
    [ -n "$line" ] || continue

    case "$line" in
      *"not found"*)
        echo "Bundled llvm-symbolizer dependency missing: $line" >&2
        SYMBOLIZER_LDD_MISSING=1
        continue
        ;;
    esac

    local candidate=""
    case "$line" in
      linux-vdso.so.*)
        continue
        ;;
      *"=>"*)
        candidate="${line#*=> }"
        candidate="${candidate%% *}"
        ;;
      /*)
        candidate="${line%% *}"
        ;;
    esac

    if [ -z "$candidate" ] || [ ! -e "$candidate" ]; then
      continue
    fi

    SYMBOLIZER_DEPENDENCIES+=("$candidate")
  done < <(ldd "$binary" 2>/dev/null || true)

  return 0
}

copy_symbolizer_dependencies() {
  local dest_dir="$1"

  mkdir -p "$dest_dir"

  local candidate base
  for candidate in "${SYMBOLIZER_DEPENDENCIES[@]}"; do
    base="$(basename "$candidate")"
    if [ -e "$dest_dir/$base" ]; then
      continue
    fi

    cp -L -p "$candidate" "$dest_dir/"
    echo "Bundled symbolizer dependency $candidate" >&2
  done
}

verify_symbolizer_bundle() {
  local binary_real_path="$1"
  local dest_dir="$2"
  local suffix="${3:-}"
  local missing=0

  if [ "${SYMBOLIZER_LDD_MISSING:-0}" -ne 0 ]; then
    missing=1
  fi

  local candidate base
  for candidate in "${SYMBOLIZER_DEPENDENCIES[@]}"; do
    base="$(basename "$candidate")"
    if [ ! -e "$dest_dir/$base" ]; then
      echo "Bundled llvm-symbolizer missing copied library${suffix}: $base" >&2
      missing=1
    fi
  done

  if [ "$missing" -ne 0 ]; then
    return 1
  fi

  if ! LD_LIBRARY_PATH="$dest_dir" ldd "$binary_real_path" >/dev/null 2>&1; then
    echo "Bundled llvm-symbolizer ldd probe failed${suffix}" >&2
    return 1
  fi

  return 0
}

bundle_symbolizer() {
  local dest_dir="$1"
  local context_label="${2:-}"

  mkdir -p "$dest_dir"

  local symbolizer_realpath
  symbolizer_realpath="$(readlink -f "$EXPECTED_SYMBOLIZER")"
  local symbolizer_basename
  symbolizer_basename="$(basename "$symbolizer_realpath")"

  enumerate_symbolizer_dependencies "$symbolizer_realpath"

  local symbolizer_exec_path
  symbolizer_exec_path="$dest_dir/$symbolizer_basename"
  cp -p "$symbolizer_realpath" "$symbolizer_exec_path"
  copy_symbolizer_dependencies "$dest_dir"

  local suffix=""
  if [ -n "$context_label" ]; then
    suffix=" ($context_label)"
  fi

  if ! verify_symbolizer_bundle "$symbolizer_exec_path" "$dest_dir" "$suffix"; then
    (cd "$dest_dir" && LD_LIBRARY_PATH="$dest_dir" ldd "./$symbolizer_basename" >&2) || true
    return 1
  fi

  if ! (cd "$dest_dir" && env -i LD_LIBRARY_PATH="$dest_dir" "$symbolizer_exec_path" --version >/dev/null 2>&1); then
    echo "Bundled llvm-symbolizer self-test failed${suffix}" >&2
    (cd "$dest_dir" && LD_LIBRARY_PATH="$dest_dir" ldd "./$symbolizer_basename" >&2) || true
    return 1
  fi

  echo "Bundled llvm-symbolizer self-test passed${suffix}" >&2
}
