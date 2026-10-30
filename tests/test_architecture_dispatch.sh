#!/usr/bin/env bash
# Exercise production ELF detection through the real import_and_analyze() dispatch.
# Ghidra itself is mocked at the process boundary; argument boundaries are preserved.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "[FAIL] $*" >&2; exit 1; }
pass() { echo "[PASS] $*"; }
log_step() { :; }
log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
log_success() { printf '[SUCCESS] %s\n' "$*"; }

# Build valid synthetic ELF identities for all currently forced mappings, plus
# unsupported/truncated cases that must not receive a guessed processor.
python3 - "$TMP_DIR" <<'PYFIX'
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
manifest = []

def make_elf(elf_class, encoding, machine, length=None, flags=0):
    required = 52 if elf_class == 1 else 64
    data = bytearray(required if length is None else length)
    data[:4] = b"\x7fELF"
    if len(data) > 4:
        data[4] = elf_class
    if len(data) > 5:
        data[5] = encoding
    if len(data) > 6:
        data[6] = 1
    endian = "<" if encoding == 1 else ">"
    if len(data) >= 20:
        struct.pack_into(endian + "H", data, 18, machine)
    if len(data) >= 24:
        struct.pack_into(endian + "I", data, 20, 1)  # e_version
    flags_offset = 36 if elf_class == 1 else 48
    if len(data) >= flags_offset + 4:
        struct.pack_into(endian + "I", data, flags_offset, flags)
    size_offset = 40 if elf_class == 1 else 52
    if len(data) >= size_offset + 2:
        struct.pack_into(endian + "H", data, size_offset, required)
    return bytes(data)

cases = [
    ("x86-32-le", 1, 1, 3, "x86:LE:32:default", None),
    ("x86-64-le", 2, 1, 62, "x86:LE:64:default", None),
    ("arm-32-le", 1, 1, 40, "ARM:LE:32:v8", None),
    ("arm-32-be", 1, 2, 40, "ARM:BE:32:v8", None),
    ("arm-32-be8", 1, 2, 40, "ARM:LEBE:32:v8LEInstruction", None),
    ("aarch64-le", 2, 1, 183, "AARCH64:LE:64:v8A", None),
    ("aarch64-be", 2, 2, 183, "AARCH64:BE:64:v8A", None),
    ("mips-32-le", 1, 1, 8, "MIPS:LE:32:default", None),
    ("mips-32-be", 1, 2, 8, "MIPS:BE:32:default", None),
    ("riscv-32-le", 1, 1, 243, "RISCV:LE:32:default", None),
    ("riscv-64-le", 2, 1, 243, "RISCV:LE:64:default", None),
    ("ppc-32-le", 1, 1, 20, "PowerPC:LE:32:default", None),
    ("ppc-32-be", 1, 2, 20, "PowerPC:BE:32:default", None),
    ("ppc64-le", 2, 1, 21, "PowerPC:LE:64:default", None),
    ("ppc64-be", 2, 2, 21, "PowerPC:BE:64:default", None),
    # MIPS64, big-endian RISC-V, and unknown machines are deliberately deferred.
    ("mips64-le-deferred", 2, 1, 8, None, None),
    ("mips64-be-deferred", 2, 2, 8, None, None),
    ("riscv-32-be-deferred", 1, 2, 243, None, None),
    ("unknown-machine-deferred", 2, 1, 0xFFFF, None, None),
    ("truncated-elf", 2, 1, 62, None, 32),
    ("invalid-elf-class", 3, 1, 62, None, None),
]

for name, elf_class, encoding, machine, processor, length in cases:
    path = root / f"{name}.elf"
    flags = 0x05800000 if name == "arm-32-be8" else 0
    path.write_bytes(make_elf(elf_class, encoding, machine, length, flags=flags))
    valid_class = elf_class in (1, 2)
    manifest.append((str(path), "elf" if length is None and valid_class else "raw",
                     processor or "none"))

raw_path = root / "unknown.bin"
raw_path.write_bytes(b"\x00" * 128)
manifest.append((str(raw_path), "raw", "none"))

(root / "manifest.tsv").write_text(
    "".join("\t".join(row) + "\n" for row in manifest), encoding="utf-8"
)
PYFIX

# Source only the production function so no CLI parsing or Ghidra installation is needed.
python3 - "$SCRIPT_DIR/ghidra-report.sh" "$TMP_DIR/import_function.sh" <<'PYEXTRACT'
import sys

source_path, output_path = sys.argv[1:]
source = open(source_path, encoding="utf-8").read()
start = source.find("import_and_analyze() {")
end = source.find("\n# Generate reports from an existing Ghidra project", start)
if start < 0 or end < 0:
    raise SystemExit("could not isolate import_and_analyze()")
with open(output_path, "w", encoding="utf-8") as handle:
    handle.write(source[start:end] + "\n")
PYEXTRACT
source "$TMP_DIR/import_function.sh"

SCRIPTS_DIR="$SCRIPT_DIR/scripts"
PROJECTS_DIR="$TMP_DIR/projects"
HEADLESS="$TMP_DIR/mock-headless"
RUN_FINDCRYPT=false
BOLD=''
NC=''
ARG_LOG="$TMP_DIR/headless-args"
CALL_LOG="$TMP_DIR/headless-calls"
mkdir -p "$PROJECTS_DIR"

detect_file_type() {
    python3 "$SCRIPTS_DIR/architecture_detector.py" type "$1"
}
detect_elf_arch() {
    python3 "$SCRIPTS_DIR/architecture_detector.py" arch "$1"
}

# Preserve each argument as a separate NUL-delimited record, exactly as exec sees it.
run_headless_logged() {
    local log_path="$1"
    local mode="$2"
    shift 2
    printf '%s\n' "$mode" >> "$CALL_LOG"
    printf '%s\0' "$@" > "$ARG_LOG"
    : > "$log_path"
    [[ "$mode" == "import" ]]
}

case_count=0
forced_count=0
while IFS=$'\t' read -r fixture expected_format expected_processor; do
    : > "$CALL_LOG"
    : > "$ARG_LOG"
    if ! import_and_analyze "$fixture" "architecture-dispatch-$case_count" >"$TMP_DIR/run.log" 2>&1; then
        cat "$TMP_DIR/run.log" >&2
        fail "import dispatch returned nonzero for $(basename "$fixture")"
    fi

    [[ "$(cat "$CALL_LOG")" == "import" ]] || fail "unexpected headless call sequence for $(basename "$fixture")"
    actual_format="$(detect_file_type "$fixture")"
    [[ "$actual_format" == "$expected_format" ]] || fail \
        "$(basename "$fixture"): expected format $expected_format, got $actual_format"

    python3 - "$ARG_LOG" "$expected_processor" "$fixture" "$SCRIPTS_DIR/architecture_detector.py" <<'PYASSERT'
import json
import pathlib
import subprocess
import sys

args_path, expected_processor, fixture, detector = sys.argv[1:]
args = pathlib.Path(args_path).read_bytes().split(b"\0")
if args and args[-1] == b"":
    args.pop()
args = [arg.decode("utf-8") for arg in args]
processor_positions = [index for index, value in enumerate(args) if value == "-processor"]

detected = json.loads(subprocess.run(
    [sys.executable, detector, "json", fixture],
    check=True, capture_output=True, text=True,
).stdout)
assert detected["format"] in {"elf", "raw"}, detected
expected = None if expected_processor == "none" else expected_processor
assert detected["processor"] == expected, (
    f"{pathlib.Path(fixture).name}: detector returned {detected['processor']!r}, "
    f"expected {expected!r}"
)

if expected is None:
    assert not processor_positions, (
        f"{pathlib.Path(fixture).name}: unsupported/unknown input was forced to "
        f"{args[processor_positions[0] + 1] if processor_positions[0] + 1 < len(args) else '<missing>'}"
    )
else:
    assert len(processor_positions) == 1, (
        f"{pathlib.Path(fixture).name}: expected one -processor argument, got {processor_positions}"
    )
    index = processor_positions[0]
    assert index + 1 < len(args), f"{pathlib.Path(fixture).name}: -processor had no value"
    assert args[index + 1] == expected, (
        f"{pathlib.Path(fixture).name}: Ghidra received {args[index + 1]!r}, expected {expected!r}"
    )
PYASSERT

    if [[ "$expected_processor" != "none" ]]; then
        forced_count=$((forced_count + 1))
    fi
    case_count=$((case_count + 1))
done < "$TMP_DIR/manifest.tsv"

[[ "$case_count" -eq 22 ]] || fail "expected 22 dispatch cases, ran $case_count"
[[ "$forced_count" -eq 15 ]] || fail "expected 15 explicit processor mappings, got $forced_count"
pass "22 synthetic inputs exercised production import dispatch; 15 exact Ghidra processor IDs were passed and 7 unsupported cases were left unforced"
