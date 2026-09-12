#!/usr/bin/env bash
#
# ghidra-report — Automated binary analysis and threat triage toolkit powered by Ghidra.
#
# Usage:
#   ./ghidra-report.sh <binary-file> [options]           # Analyze a single file
#   ./ghidra-report.sh --batch [options]                 # Analyze all files in ingress/
#   ./ghidra-report.sh --watch [options]                 # Watch ingress/ directory
#   ./ghidra-report.sh --diff <rep1.json> <rep2.json>    # Compare two reports
#   ./ghidra-report.sh --dashboard [port]                # Launch interactive web dashboard
#   ./ghidra-report.sh --search <term>                   # Search historical reports
#   ./ghidra-report.sh --list-projects                   # Show all Ghidra projects
#   ./ghidra-report.sh --purge-projects                  # Clean temporary Ghidra projects
#   ./ghidra-report.sh --help                            # Show usage
#
# Options:
#   --format <txt|json|md|html|sarif|yar|misp|all>       # Report formats (default: all)
#   --parallel, -j [N]                                   # Concurrent batch workers (default: 1)
#   --webhook <url>                                      # Alert webhook URL (Slack/Discord)
#   --full-disasm                                        # Disassemble all functions
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INGRESS_DIR="$SCRIPT_DIR/ingress"
OUTPUT_DIR="$SCRIPT_DIR/output"
PROJECTS_DIR="$SCRIPT_DIR/projects"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

# Ghidra Flatpak and system paths
GHIDRA_ROOT="${GHIDRA_ROOT:-}"
if [ -z "$GHIDRA_ROOT" ] || [ ! -d "$GHIDRA_ROOT" ]; then
    for candidate in \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/x86_64/stable/active/files/lib/ghidra" \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/ghidra" \
        "/opt/ghidra" \
        "/usr/share/ghidra"; do
        if [ -d "$candidate" ]; then
            GHIDRA_ROOT="$candidate"
            break
        fi
    done
fi
HEADLESS="$SCRIPT_DIR/run-headless.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Default settings
FORMAT="all"
FULL_DISASM="false"
PARALLEL_JOBS="1"
WEBHOOK_URL=""
RUN_FINDCRYPT="false"

print_banner() {
    echo -e "${CYAN}"
    echo "   ██████╗ ██╗  ██╗██╗██████╗ ██████╗  █████╗ "
    echo "  ██╔════╝ ██║  ██║██║██╔══██╗██╔══██╗██╔══██╗"
    echo "  ██║  ███╗███████║██║██║  ██║██████╔╝███████║"
    echo "  ██║   ██║██╔══██║██║██║  ██║██╔══██╗██╔══██║"
    echo "  ╚██████╔╝██║  ██║██║██████╔╝██║  ██║██║  ██║"
    echo "   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"
    echo "   ████████╗ ██████╗  ██████╗ ██╗     ███████╗"
    echo "   ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝"
    echo "      ██║   ██║   ██║██║   ██║██║     ███████╗"
    echo "      ██║   ██║   ██║██║   ██║██║     ╚════██║"
    echo "      ██║   ╚██████╔╝╚██████╔╝███████╗███████║"
    echo "      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝"
    echo -e "${NC}${CYAN}  ░▒▓█ ghidra-report v0.2.0 · binary triage █▓▒░${NC}"
    echo ""
}

log_info()    { echo -e "  ${BLUE}[INFO]${NC}  $*"; }
log_success() { echo -e "  ${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "  ${RED}[ERROR]${NC} $*"; }
log_step()    { echo -e "  ${CYAN}[STEP]${NC}  $*"; }

# Ensure directories exist
setup_dirs() {
    mkdir -p "$INGRESS_DIR" "$OUTPUT_DIR" "$PROJECTS_DIR" "$SCRIPTS_DIR"
}

# Validate prerequisites
check_prereqs() {
    if [ ! -d "$GHIDRA_ROOT" ]; then
        log_error "Ghidra installation not found at: $GHIDRA_ROOT"
        exit 1
    fi
    if [ ! -x "$HEADLESS" ]; then
        log_error "Headless launcher not executable: $HEADLESS"
        exit 1
    fi
}

# Load user configuration from ~/.config/ghidra-report/config.json if available
load_user_config() {
    local cfg="$HOME/.config/ghidra-report/config.json"
    if [ -f "$cfg" ]; then
        local def_fmt def_hook def_jobs
        def_fmt="$(python3 -c "import json; print(json.load(open('$cfg')).get('default_format', ''))" 2>/dev/null || true)"
        def_hook="$(python3 -c "import json; print(json.load(open('$cfg')).get('webhook_url', ''))" 2>/dev/null || true)"
        def_jobs="$(python3 -c "import json; print(json.load(open('$cfg')).get('parallel_jobs', ''))" 2>/dev/null || true)"

        [ -n "$def_fmt" ] && [ "$FORMAT" = "all" ] && FORMAT="$def_fmt"
        [ -n "$def_hook" ] && [ -z "$WEBHOOK_URL" ] && WEBHOOK_URL="$def_hook"
        [ -n "$def_jobs" ] && [ "$PARALLEL_JOBS" = "1" ] && PARALLEL_JOBS="$def_jobs"
    fi
}

# Detect file format from extension and magic bytes
detect_file_type() {
    local file="$1"
    local ext="${file##*.}"
    ext="$(echo "$ext" | tr '[:upper:]' '[:lower:]')"

    case "$ext" in
        sfc|smc|fig)
            echo "snes"
            return
            ;;
        gba)
            echo "gba"
            return
            ;;
        z64|n64|v64)
            echo "n64"
            return
            ;;
        psx)
            echo "psx"
            return
            ;;
        exe|dll|sys)
            echo "pe"
            return
            ;;
        elf|so|o)
            echo "elf"
            return
            ;;
        rom|bin)
            # Will check magic bytes below before falling back to snes
            ;;
    esac

    # Magic byte checks
    local magic_8
    magic_8="$(head -c 8 "$file" 2>/dev/null || true)"
    local magic_4="${magic_8:0:4}"

    if [ "$magic_4" = $'\x7fELF' ]; then
        echo "elf"
        return
    fi
    if [ "${magic_8:0:2}" = "MZ" ]; then
        echo "pe"
        return
    fi
    if [ "$magic_8" = "PS-X EXE" ]; then
        echo "psx"
        return
    fi

    local hex4
    hex4="$(head -c 4 "$file" 2>/dev/null | xxd -p 2>/dev/null || od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n' || true)"
    if [ "$hex4" = "80371240" ] || [ "$hex4" = "37804012" ] || [ "$hex4" = "40123780" ]; then
        echo "n64"
        return
    fi

    if [ "$ext" = "sfc" ] || [ "$ext" = "smc" ] || [ "$ext" = "rom" ] || [ "$ext" = "bin" ]; then
        echo "snes"
        return
    fi

    echo "raw"
}

# Auto-detect ELF architecture from header e_machine
detect_elf_arch() {
    local file="$1"
    python3 -c "
import struct
try:
    with open('$file', 'rb') as f:
        hdr = f.read(20)
    if hdr[:4] == b'\x7fELF':
        endian = '<' if hdr[5] == 1 else '>'
        mach = struct.unpack(endian + 'H', hdr[18:20])[0]
        arch_map = {3: 'x86:LE:32:default', 62: 'x86:LE:64:default', 40: 'ARM:LE:32:v8', 183: 'AARCH64:LE:64:v8A', 8: 'MIPS:BE:32:default', 243: 'RISCV:LE:64:RV64GC', 20: 'PowerPC:BE:32:default'}
        print(arch_map.get(mach, f'e_machine {mach}'))
except Exception:
    pass
"
}

# Generate a project name from a binary path
project_name_for() {
    local file="$1"
    local base
    base="$(basename "$file")"
    echo "$base" | tr -cs 'a-zA-Z0-9_' '_'
}

# Import binary into a Ghidra project and run analysis
import_and_analyze() {
    local binary_path="$1"
    local project_name
    project_name="$(project_name_for "$binary_path")"
    local file_type
    file_type="$(detect_file_type "$binary_path")"

    log_step "Importing: ${BOLD}$(basename "$binary_path")${NC} → project: ${BOLD}$project_name${NC}"

    local extra_args=()
    case "$file_type" in
        snes)
            log_info "SNES ROM detected — attempting import with SnesRomLoader..."
            extra_args+=(-loader "SnesRomLoader")
            ;;
        gba)
            log_info "Game Boy Advance ROM detected — attempting import with GBALoader..."
            extra_args+=(-loader "GBALoader")
            ;;
        n64)
            log_info "Nintendo 64 ROM detected — attempting import with N64LoaderWVLoader..."
            extra_args+=(-loader "N64LoaderWVLoader")
            ;;
        psx)
            log_info "PlayStation executable detected — attempting import with PsxLoader..."
            extra_args+=(-loader "PsxLoader")
            ;;
        pe)
            log_info "PE executable detected"
            ;;
        elf)
            log_info "ELF binary detected"
            local elf_arch
            elf_arch="$(detect_elf_arch "$binary_path")"
            if [ -n "$elf_arch" ]; then
                log_info "ELF Architecture auto-detected: ${BOLD}$elf_arch${NC}"
            fi
            ;;
        *)
            log_info "Importing as raw binary"
            ;;
    esac

    local post_scripts=()
    if [ "$RUN_FINDCRYPT" = "true" ]; then
        log_info "FindCrypt enabled — scanning for cryptographic constants..."
        post_scripts+=(-scriptPath "$SCRIPTS_DIR/lib" -postScript FindCrypt.java)
    fi

    # Remove existing project if re-importing
    if [ -d "$PROJECTS_DIR/${project_name}.rep" ]; then
        log_warn "Removing existing project: $project_name"
        rm -rf "$PROJECTS_DIR/${project_name}.rep" "$PROJECTS_DIR/${project_name}.gpr"
    fi

    log_step "Running Ghidra headless import + analysis..."
    log_info "This may take a while for large binaries."
    echo ""

    local import_log
    import_log="$(mktemp)"

    "$HEADLESS" \
        "$PROJECTS_DIR" "$project_name" \
        -import "$binary_path" \
        "${extra_args[@]}" \
        "${post_scripts[@]}" \
        -analysisTimeoutPerFile 300 \
        2>&1 | tee "$import_log" | while IFS= read -r line; do
            if echo "$line" | grep -qE "INFO.*[Ii]mport|INFO.*[Aa]nalys|INFO.*Loaded|ERROR|WARN"; then
                echo -e "    ${DIM}$line${NC}"
            fi
        done

    # Check if import failed (loader rejected the file)
    if grep -q "Import failed\|No load spec found\|could not successfully load" "$import_log"; then
        if [ "$file_type" = "snes" ]; then
            log_warn "SNES ROM Loader rejected file (possibly non-standard header)."
            log_info "Falling back to raw import with 65816 processor..."
            echo ""

            rm -rf "$PROJECTS_DIR/${project_name}.rep" "$PROJECTS_DIR/${project_name}.gpr"

            "$HEADLESS" \
                "$PROJECTS_DIR" "$project_name" \
                -import "$binary_path" \
                -processor "65816:LE:24:snes" \
                -analysisTimeoutPerFile 300 \
                2>&1 | tee "$import_log" | while IFS= read -r line; do
                    if echo "$line" | grep -qE "INFO.*[Ii]mport|INFO.*[Aa]nalys|ERROR|WARN"; then
                        echo -e "    ${DIM}$line${NC}"
                    fi
                done

            if grep -q "Import failed" "$import_log"; then
                log_error "Import failed even with raw 65816 fallback."
                rm -f "$import_log"
                return 1
            fi
            log_success "Raw 65816 import + analysis complete."
        else
            log_error "Import failed."
            rm -f "$import_log"
            return 1
        fi
    else
        log_success "Import + analysis complete."
    fi
    rm -f "$import_log"
    echo ""
}

# Generate reports from an existing Ghidra project in a dedicated binary folder
generate_report() {
    local project_name="$1"
    local binary_name="$2"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    local file_output_dir="$OUTPUT_DIR/$binary_name"
    mkdir -p "$file_output_dir"
    local report_base="$file_output_dir/${binary_name}_report_${timestamp}"

    log_step "Generating report(s) for: ${BOLD}$binary_name${NC} [Formats: ${BOLD}$FORMAT${NC}]"

    local extra_script_flag=""
    if [ "$FULL_DISASM" = "true" ]; then
        extra_script_flag="--full-disasm"
    fi

    "$HEADLESS" \
        "$PROJECTS_DIR" "$project_name" \
        -process "$binary_name" \
        -readOnly \
        -noanalysis \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript ExportFullReport.java "$report_base" "$FORMAT" "$extra_script_flag" \
        2>&1 | while IFS= read -r line; do
            if echo "$line" | grep -qE "report:|Report written|rule:|ERROR|Script"; then
                echo -e "    ${DIM}$line${NC}"
            fi
        done

    local txt_report="${report_base}.txt"
    local json_report="${report_base}.json"

    if [ -f "$txt_report" ] || [ -f "$json_report" ]; then
        echo ""
        log_success "Reports generated successfully in: ${BOLD}$file_output_dir${NC}"

        for ext in txt json md html sarif yar misp.json; do
            local f="${report_base}.${ext}"
            if [ -f "$f" ]; then
                local sz
                sz="$(du -h "$f" | cut -f1)"
                echo -e "    ${GREEN}●${NC} $(basename "$f")  ${DIM}($sz)${NC}"
                ln -sf "$(basename "$f")" "$file_output_dir/report_latest.${ext}"
            fi
        done
        echo -e "    ${CYAN}➜${NC} Latest symlinks created: ${DIM}$file_output_dir/report_latest.*${NC}"

        # Index report in SQLite database
        if [ -f "$json_report" ] && [ -f "$SCRIPTS_DIR/index_report.py" ]; then
            python3 "$SCRIPTS_DIR/index_report.py" index "$json_report" >/dev/null 2>&1 || true
        fi

        # Send Webhook Alert if configured
        if [ -n "$WEBHOOK_URL" ] && [ -f "$json_report" ]; then
            python3 -c "
import json, urllib.request
try:
    with open('$json_report') as f:
        d = json.load(f)
    t = d.get('threat_summary', {})
    score = t.get('risk_score', 0)
    level = t.get('risk_level', 'UNKNOWN')
    payload = {
        'text': f'🚨 *ghidra-report Triage Alert*: `{d.get(\"file\")}`\n*Threat Score*: {score}/100 [{level}]\n*Format*: {d.get(\"format_label\")}',
        'binary': d.get('file'),
        'score': score,
        'level': level
    }
    req = urllib.request.Request('$WEBHOOK_URL', data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=5)
except Exception:
    pass
" >/dev/null 2>&1 || true
        fi

        if [ -f "$txt_report" ]; then
            echo ""
            echo -e "  ${BOLD}── Quick Triage Summary ──${NC}"
            grep -A 8 "THREAT TRIAGE SUMMARY" "$txt_report" 2>/dev/null || true
            echo ""
            grep -E "Functions identified:|Language:|Estimated code coverage:" "$txt_report" 2>/dev/null || true
            echo ""
        fi
    else
        log_error "Report generation failed — no output files created."
        return 1
    fi
}

# Process a single binary: import, analyze, report
process_binary() {
    local binary_path="$1"
    local force_reimport="${2:-false}"

    if [ ! -f "$binary_path" ]; then
        log_error "File not found: $binary_path"
        exit 1
    fi

    local binary_name
    binary_name="$(basename "$binary_path")"
    local project_name
    project_name="$(project_name_for "$binary_path")"

    if [ -f "$PROJECTS_DIR/${project_name}.gpr" ] && [ "$force_reimport" != "true" ]; then
        log_info "Project already exists: $project_name"
        log_info "Use --reimport to force re-import with fresh analysis."
    else
        if ! import_and_analyze "$binary_path"; then
            log_error "Skipping report generation due to import failure."
            return 1
        fi
    fi

    generate_report "$project_name" "$binary_name"
}

# Batch process all files in ingress/ with optional parallel worker dispatch
batch_process() {
    log_step "Scanning ingress directory for binaries..."
    local files=()
    while IFS= read -r f; do
        files+=("$f")
    done < <(find "$INGRESS_DIR" -type f \( \
        -iname "*.bin" -o -iname "*.sfc" -o -iname "*.smc" \
        -o -iname "*.exe" -o -iname "*.dll" -o -iname "*.sys" \
        -o -iname "*.elf" -o -iname "*.so" -o -iname "*.o" \
        -o -iname "*.rom" -o -iname "*.fig" \
    \) | sort)

    local total="${#files[@]}"
    if [ "$total" -eq 0 ]; then
        log_warn "No supported binaries found in $INGRESS_DIR"
        log_info "Supported extensions: .bin .sfc .smc .exe .dll .sys .elf .so .o .rom .fig"
        return
    fi

    local jobs="${PARALLEL_JOBS:-1}"
    if [ "$jobs" -gt 1 ]; then
        log_step "Dispatching $total file(s) across ${BOLD}$jobs parallel workers${NC}..."
        local running=0
        local pids=()
        for file in "${files[@]}"; do
            (
                process_binary "$file" "false"
            ) &
            pids+=($!)
            running=$((running + 1))
            if [ "$running" -ge "$jobs" ]; then
                wait -n 2>/dev/null || wait "${pids[0]}" 2>/dev/null || true
                running=$((running - 1))
            fi
        done
        wait
    else
        local count=0
        for file in "${files[@]}"; do
            count=$((count + 1))
            echo ""
            echo -e "  ${BOLD}━━━ File $count of $total: $(basename "$file") ━━━${NC}"
            process_binary "$file" "false" || log_error "Failed processing: $(basename "$file")"
        done
    fi

    echo ""
    log_success "Batch processing complete: $total file(s) analyzed."
}

# Compare two reports (JSON format) with standardized semantic findings lifecycle
diff_reports() {
    local r1="$1"
    local r2="$2"

    if [ -d "$OUTPUT_DIR/$r1" ] && [ -f "$OUTPUT_DIR/$r1/report_latest.json" ]; then
        r1="$OUTPUT_DIR/$r1/report_latest.json"
    elif [ -d "$r1" ] && [ -f "$r1/report_latest.json" ]; then
        r1="$r1/report_latest.json"
    fi

    if [ -d "$OUTPUT_DIR/$r2" ] && [ -f "$OUTPUT_DIR/$r2/report_latest.json" ]; then
        r2="$OUTPUT_DIR/$r2/report_latest.json"
    elif [ -d "$r2" ] && [ -f "$r2/report_latest.json" ]; then
        r2="$r2/report_latest.json"
    fi

    if [ ! -f "$r1" ] || [ ! -f "$r2" ]; then
        log_error "Both report JSON files must exist for comparison."
        log_info "Usage: $0 --diff <report1.json|binary1> <report2.json|binary2>"
        exit 1
    fi

    log_step "Comparing reports:"
    echo -e "    Target A: ${BOLD}$r1${NC}"
    echo -e "    Target B: ${BOLD}$r2${NC}"
    echo ""

    python3 - "$r1" "$r2" <<'PYDIFF'
import json, sys

r1 = sys.argv[1]
r2 = sys.argv[2]

try:
    with open(r1) as f1, open(r2) as f2:
        d1 = json.load(f1)
        d2 = json.load(f2)
except Exception as e:
    print(f"Error reading JSON reports: {e}")
    sys.exit(1)

print('=' * 80)
print('  REPORT COMPARISON')
print('=' * 80)
print(f'  Target A: {d1.get("file")} ({d1.get("format_label")})')
print(f'  Target B: {d2.get("file")} ({d2.get("format_label")})')
print()

# Threat Score Diff
s1 = d1.get('threat_summary', {}).get('risk_score', 0)
s2 = d2.get('threat_summary', {}).get('risk_score', 0)
l1 = d1.get('threat_summary', {}).get('risk_level', 'UNKNOWN')
l2 = d2.get('threat_summary', {}).get('risk_level', 'UNKNOWN')
diff_s = s2 - s1
sign = '+' if diff_s > 0 else ''
print(f'  Threat Score: {s1} ({l1}) -> {s2} ({l2}) [{sign}{diff_s}]')

# Hashes
h1 = d1.get('hashes', {}).get('sha256', '')
h2 = d2.get('hashes', {}).get('sha256', '')
print(f'  SHA256 Match: {"IDENTICAL" if h1 == h2 else "DIFFERENT"}')
print()

# Function counts
f1 = d1.get('analysis_stats', {}).get('function_count', 0)
f2 = d2.get('analysis_stats', {}).get('function_count', 0)
print(f'  Function Count: {f1} -> {f2} ({f2 - f1:+d})')

# Memory blocks
b1 = {b['name']: b for b in d1.get('memory_blocks', [])}
b2 = {b['name']: b for b in d2.get('memory_blocks', [])}
all_blocks = sorted(set(b1.keys()).union(set(b2.keys())))
print('\n  Section / Memory Block Diffs:')
print(f'  {"Block":<18} {"A Size":<10} {"B Size":<10} {"A Entropy":<10} {"B Entropy":<10} {"Status"}')
print('  ' + '-' * 70)
for bname in all_blocks:
    if bname in b1 and bname in b2:
        sz1 = b1[bname].get('size', 0)
        sz2 = b2[bname].get('size', 0)
        e1 = b1[bname].get('entropy', 0.0)
        e2 = b2[bname].get('entropy', 0.0)
        chg = '[UPDATED]' if (sz1 != sz2 or abs(e1 - e2) > 0.05) else '[UNCHANGED]'
        print(f'  {bname:<18} {sz1:<10} {sz2:<10} {e1:<10.2f} {e2:<10.2f} {chg}')
    elif bname in b2:
        print(f'  {bname:<18} {"-":<10} {b2[bname].get("size",0):<10} {"-":<10} {b2[bname].get("entropy",0.0):<10.2f} [NEW]')
    else:
        print(f'  {bname:<18} {b1[bname].get("size",0):<10} {"-":<10} {b1[bname].get("entropy",0.0):<10.2f} {"-":<10} [ABSENT]')

# Suspicious APIs (Semantic Lifecycle)
a1 = {f"{a.get('library')}!{a.get('function')}" for a in d1.get('suspicious_apis', [])}
a2 = {f"{a.get('library')}!{a.get('function')}" for a in d2.get('suspicious_apis', [])}
added_apis = a2 - a1
removed_apis = a1 - a2
unchanged_apis = a1.intersection(a2)

print('\n  Suspicious APIs Lifecycle:')
for api in sorted(added_apis):
    print(f'    [NEW]      + {api}')
for api in sorted(removed_apis):
    print(f'    [ABSENT]   - {api}')
for api in sorted(unchanged_apis):
    print(f'    [UNCHANGED]  {api}')
if not (added_apis or removed_apis or unchanged_apis):
    print('    (none)')

print(f'\n  Lifecycle Summary: {len(added_apis)} new, {len(removed_apis)} absent, {len(unchanged_apis)} unchanged APIs.')
print('=' * 80)
PYDIFF
}

# Start the interactive web dashboard
serve_dashboard() {
    local port="${1:-8080}"
    log_step "Starting ghidra-report interactive dashboard on http://localhost:${port}..."
    log_info "Browse reports, search IOCs, and diff binaries at: ${BOLD}http://localhost:${port}/${NC}"
    log_info "Press Ctrl+C to stop."
    echo ""
    if [ -f "$SCRIPTS_DIR/dashboard.py" ]; then
        python3 "$SCRIPTS_DIR/dashboard.py" "$port"
    else
        python3 -m http.server "$port" --directory "$SCRIPT_DIR"
    fi
}

# Purge Ghidra project files to reclaim disk space
purge_projects() {
    log_step "Cleaning temporary Ghidra projects in $PROJECTS_DIR..."
    if ls "$PROJECTS_DIR"/*.gpr 1>/dev/null 2>&1 || ls -d "$PROJECTS_DIR"/*.rep 1>/dev/null 2>&1; then
        rm -rf "$PROJECTS_DIR"/*.gpr "$PROJECTS_DIR"/*.rep
        log_success "Purged all temporary Ghidra projects."
    else
        log_info "No projects to purge."
    fi
}

# List existing Ghidra projects
list_projects() {
    log_info "Ghidra projects in $PROJECTS_DIR:"
    echo ""
    if ls "$PROJECTS_DIR"/*.gpr 1>/dev/null 2>&1; then
        for gpr in "$PROJECTS_DIR"/*.gpr; do
            local name
            name="$(basename "$gpr" .gpr)"
            local rep_size="unknown"
            if [ -d "$PROJECTS_DIR/${name}.rep" ]; then
                rep_size="$(du -sh "$PROJECTS_DIR/${name}.rep" | cut -f1)"
            fi
            echo -e "    ${GREEN}●${NC} $name  ${DIM}($rep_size)${NC}"
        done
    else
        echo -e "    ${DIM}(none)${NC}"
    fi
    echo ""
}

# Watch ingress directory and automatically analyze new files
watch_ingress() {
    log_step "Starting zero-touch ingress watcher on: ${BOLD}$INGRESS_DIR${NC}"
    log_info "Drop binaries into $INGRESS_DIR to trigger automatic analysis."
    log_info "Press Ctrl+C to exit."
    echo ""

    if command -v inotifywait >/dev/null 2>&1; then
        log_info "Using inotifywait event engine..."
        inotifywait -m -e close_write,moved_to --format "%w%f" "$INGRESS_DIR" | while read -r new_file; do
            if [ -f "$new_file" ]; then
                echo ""
                log_step "New file detected: ${BOLD}$(basename "$new_file")${NC}"
                process_binary "$new_file" "false"
            fi
        done
    else
        log_warn "inotifywait not installed. Using portable polling engine (2s interval)..."
        local processed_file
        processed_file="$(mktemp)"
        find "$INGRESS_DIR" -maxdepth 2 -type f > "$processed_file"

        trap "rm -f \"$processed_file\"; exit 0" INT TERM

        while true; do
            while IFS= read -r f; do
                if ! grep -qF "$f" "$processed_file" 2>/dev/null; then
                    echo ""
                    log_step "New file detected: ${BOLD}$(basename "$f")${NC}"
                    echo "$f" >> "$processed_file"
                    process_binary "$f" "false"
                fi
            done < <(find "$INGRESS_DIR" -maxdepth 2 -type f 2>/dev/null)
            sleep 2
        done
        rm -f "$processed_file"
    fi
}

# Capability Rule Engine
evaluate_capabilities() {
    local target="$1"
    local rep="$target"
    if [ -z "$rep" ]; then
        rep="$(find "$OUTPUT_DIR" -name "report_latest.json" | head -n 1)"
        if [ -z "$rep" ]; then
            log_error "Usage: $0 --rules <report.json|binary_name>"
            exit 1
        fi
    fi
    if [ ! -f "$rep" ] && [ -f "$OUTPUT_DIR/$rep/report_latest.json" ]; then
        rep="$OUTPUT_DIR/$rep/report_latest.json"
    fi
    if [ ! -f "$rep" ]; then
        log_error "Report file not found: $rep"
        exit 1
    fi
    python3 "$SCRIPTS_DIR/capability_engine.py" evaluate "$rep" "$SCRIPT_DIR/rules"
}

# Dynamic Trace Correlator
correlate_trace() {
    local trace="$1"
    local static_target="${2:-}"
    if [ -z "$trace" ]; then
        log_error "Usage: $0 --trace <trace.json> [static_report.json]"
        exit 1
    fi
    local rep="$static_target"
    if [ -z "$rep" ]; then
        rep="$(find "$OUTPUT_DIR" -name "report_latest.json" | head -n 1)"
    fi
    if [ ! -f "$rep" ] && [ -f "$OUTPUT_DIR/$rep/report_latest.json" ]; then
        rep="$OUTPUT_DIR/$rep/report_latest.json"
    fi
    if [ ! -f "$rep" ]; then
        log_error "Static report file not found: $rep"
        exit 1
    fi
    python3 "$SCRIPTS_DIR/trace_correlator.py" correlate "$rep" "$trace"
}

# CMSIS-SVD Inspector
inspect_svd() {
    local svd="$1"
    if [ -z "$svd" ] || [ ! -f "$svd" ]; then
        log_error "Usage: $0 --svd <file.svd>"
        exit 1
    fi
    python3 "$SCRIPTS_DIR/svd_injector.py" inspect "$svd"
}

# Search historical analysis database
search_reports() {
    local term="$1"
    if [ -z "$term" ]; then
        log_error "Please provide a search term: $0 --search <term>"
        exit 1
    fi
    python3 "$SCRIPTS_DIR/index_report.py" search "$term"
}

# Show help
show_help() {
    print_banner
    echo "  USAGE:"
    echo "    ./ghidra-report.sh <binary-file> [options]           Analyze a single file"
    echo "    ./ghidra-report.sh --batch [options]                 Analyze all files in ingress/"
    echo "    ./ghidra-report.sh --watch [options]                 Continuous ingress directory watcher"
    echo "    ./ghidra-report.sh --reimport <binary-file>          Re-import with fresh analysis"
    echo "    ./ghidra-report.sh --diff <rep1.json> <rep2.json>    Compare two reports"
    echo "    ./ghidra-report.sh --carve <binary-file> [out_dir]   Scan & carve embedded firmware containers"
    echo "    ./ghidra-report.sh --rules [rep.json|binary]         Evaluate YAML capability rules (CAPA style)"
    echo "    ./ghidra-report.sh --trace <trace.json> [rep.json]   Correlate dynamic sandbox execution log"
    echo "    ./ghidra-report.sh --svd <file.svd>                  Inspect and inject CMSIS-SVD peripherals"
    echo "    ./ghidra-report.sh --search <term>                   Search historical reports database"
    echo "    ./ghidra-report.sh --dashboard [port]                Launch interactive web dashboard"
    echo "    ./ghidra-report.sh --list-projects                   Show existing Ghidra projects"
    echo "    ./ghidra-report.sh --purge-projects                  Clean Ghidra temporary project cache"
    echo "    ./ghidra-report.sh --help                            Show this help"
    echo ""
    echo "  OPTIONS:"
    echo "    --format <txt|json|md|html|sarif|yar|misp|all>       Output formats (default: all)"
    echo "    --parallel, -j [N]                                   Run batch analysis with N concurrent workers"
    echo "    --findcrypt                                          Scan for 100+ cryptographic constants (AES, ChaCha, MD5, SHA)"
    echo "    --webhook <url>                                      Send triage alert to Slack/Discord/Webhook"
    echo "    --full-disasm                                        Disassemble all functions"
    echo ""
    echo "  DIRECTORIES:"
    echo "    ingress/   Drop binary files here for analysis"
    echo "    output/    Reports are written here (.txt, .json, .md, .html, .sarif, .yar, .misp.json)"
    echo "    scripts/   Ghidra analysis scripts (Java)"
    echo ""
    echo "  SUPPORTED FORMATS:"
    echo "    PE Executables  .exe .dll .sys"
    echo "    ELF Binaries    .elf .so .o"
    echo "    SNES ROMs       .sfc .smc .bin .rom .fig"
    echo "    Raw Binaries    .bin"
    echo ""
}

# ── Argument Parsing ──

setup_dirs
check_prereqs
load_user_config

ACTION=""
TARGET_FILE=""
TARGET_DIFF1=""
TARGET_DIFF2=""
SEARCH_TERM=""
TARGET_TRACE=""
TARGET_SVD="" 

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            show_help
            exit 0
            ;;
        --batch|-b)
            ACTION="batch"
            shift
            ;;
        --watch|-w)
            ACTION="watch"
            shift
            ;;
        --dashboard|--serve|-s)
            ACTION="serve"
            shift
            if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
                SERVE_PORT="$1"
                shift
            fi
            ;;
        --search|-q)
            ACTION="search"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                SEARCH_TERM="$1"
                shift
            fi
            ;;
        --list-projects|-l)
            ACTION="list-projects"
            shift
            ;;
        --rules|--capabilities)
            ACTION="rules"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                TARGET_FILE="$1"
                shift
            fi
            ;;
        --trace)
            ACTION="trace"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                TARGET_TRACE="$1"
                shift
            fi
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                TARGET_FILE="$1"
                shift
            fi
            ;;
        --svd)
            ACTION="svd"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                TARGET_SVD="$1"
                shift
            fi
            ;;
        --carve|-c)
            ACTION="carve"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                TARGET_FILE="$1"
                shift
            fi
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                CARVE_OUTDIR="$1"
                shift
            fi
            ;;
        --purge-projects|--clean)
            ACTION="purge-projects"
            shift
            ;;
        --reimport|-r)
            ACTION="reimport"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                TARGET_FILE="$1"
                shift
            fi
            ;;
        --diff|-d)
            ACTION="diff"
            shift
            if [[ $# -ge 2 ]]; then
                TARGET_DIFF1="$1"
                TARGET_DIFF2="$2"
                shift 2
            else
                log_error "--diff requires two JSON report files"
                exit 1
            fi
            ;;
        --format)
            shift
            if [[ $# -gt 0 ]]; then
                FORMAT="$1"
                shift
            fi
            ;;
        --parallel|-j)
            shift
            if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
                PARALLEL_JOBS="$1"
                shift
            else
                PARALLEL_JOBS="2"
            fi
            ;;
        --webhook)
            shift
            if [[ $# -gt 0 ]]; then
                WEBHOOK_URL="$1"
                shift
            fi
            ;;
        --detect-type)
            shift
            if [[ $# -gt 0 ]]; then
                detect_file_type "$1"
                exit 0
            fi
            ;;
        --findcrypt)
            RUN_FINDCRYPT="true"
            shift
            ;;
        --full-disasm)
            FULL_DISASM="true"
            shift
            ;;
        *)
            if [ -z "$TARGET_FILE" ] && [ -z "$ACTION" ]; then
                TARGET_FILE="$1"
                ACTION="analyze"
            fi
            shift
            ;;
    esac
done

case "$ACTION" in
    batch)
        print_banner
        batch_process
        ;;
    watch)
        print_banner
        watch_ingress
        ;;
    search)
        search_reports "$SEARCH_TERM"
        ;;
    list-projects)
        print_banner
        list_projects
        ;;
    purge-projects)
        print_banner
        purge_projects
        ;;
    carve)
        print_banner
        if [ -z "$TARGET_FILE" ]; then
            log_error "Usage: $0 --carve <binary-file> [out_dir]"
            exit 1
        fi
        CARVE_OUTDIR="${CARVE_OUTDIR:-$OUTPUT_DIR/$(basename "$TARGET_FILE")_carved}"
        python3 "$SCRIPTS_DIR/firmware_carver.py" scan "$TARGET_FILE"
        python3 "$SCRIPTS_DIR/firmware_carver.py" extract "$TARGET_FILE" "$CARVE_OUTDIR"
        ;;
    rules)
        print_banner
        evaluate_capabilities "${TARGET_FILE:-}"
        ;;
    trace)
        print_banner
        correlate_trace "${TARGET_TRACE:-}" "${TARGET_FILE:-}"
        ;;
    svd)
        print_banner
        inspect_svd "${TARGET_SVD:-}"
        ;;
    serve)
        print_banner
        serve_dashboard "${SERVE_PORT:-8080}"
        ;;
    reimport)
        print_banner
        if [ -z "$TARGET_FILE" ]; then
            log_error "Usage: $0 --reimport <binary-file>"
            exit 1
        fi
        process_binary "$TARGET_FILE" true
        ;;
    diff)
        print_banner
        diff_reports "$TARGET_DIFF1" "$TARGET_DIFF2"
        ;;
    analyze)
        print_banner
        if [ -z "$TARGET_FILE" ]; then
            log_error "No binary file specified."
            echo ""
            show_help
            exit 1
        fi
        process_binary "$TARGET_FILE" false
        ;;
    *)
        print_banner
        show_help
        exit 0
        ;;
esac
