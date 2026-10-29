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
source "$SCRIPTS_DIR/batch_runner.sh"
source "$SCRIPTS_DIR/headless_log.sh"
source "$SCRIPTS_DIR/output_lock.sh"

# Ghidra Flatpak and system paths
GHIDRA_ROOT="${GHIDRA_ROOT:-}"
if [ -z "$GHIDRA_ROOT" ] || [ ! -d "$GHIDRA_ROOT" ]; then
    for candidate in \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/x86_64/stable/active/files/lib/ghidra" \
        "/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra" \
        "/opt/ghidra" \
        "/usr/share/ghidra"; do
        if [ -d "$candidate" ]; then
            GHIDRA_ROOT="$candidate"
            break
        fi
    done
fi
# Pass the same detected installation to the child launcher.
export GHIDRA_ROOT
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

# Format and processor detection are delegated to the stdlib parser. File extensions
# are hints only: unknown .bin files must never be guessed to be SNES ROMs.
detect_file_type() {
    python3 "$SCRIPTS_DIR/architecture_detector.py" type "$1"
}

detect_elf_arch() {
    python3 "$SCRIPTS_DIR/architecture_detector.py" arch "$1"
}

# Generate a project name from a binary path
project_name_for() {
    local file="$1"
    python3 "$SCRIPTS_DIR/project_identity.py" project "$file" "${RUN_FINDCRYPT:-false}" "${GHIDRA_ROOT:-}"
}

output_key_for() {
    local file="$1"
    python3 "$SCRIPTS_DIR/project_identity.py" output "$file"
}

# Import binary into a Ghidra project and run analysis
import_and_analyze() {
    local binary_path="$1"
    local project_name="${2:-}"
    if [ -z "$project_name" ]; then
        project_name="$(project_name_for "$binary_path")" || return $?
    fi
    local file_type
    file_type="$(detect_file_type "$binary_path")"

    log_step "Importing: ${BOLD}$(basename "$binary_path")${NC} → project: ${BOLD}$project_name${NC}"

    local extra_args=()
    local detection_evidence
    detection_evidence="$(python3 "$SCRIPTS_DIR/architecture_detector.py" evidence "$binary_path")"
    log_info "Detection evidence: $detection_evidence"
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
                log_info "ELF processor selected: ${BOLD}$elf_arch${NC}"
                extra_args+=(-processor "$elf_arch")
            else
                log_warn "ELF class/endianness/machine combination has no supported processor mapping; defer language selection to Ghidra."
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
    local import_status=0

    if run_headless_logged "$import_log" import \
        "$HEADLESS" \
        "$PROJECTS_DIR" "$project_name" \
        -import "$binary_path" \
        "${extra_args[@]}" \
        "${post_scripts[@]}" \
        -analysisTimeoutPerFile 300; then
        import_status=0
    else
        import_status=$?
    fi

    # Diagnostic text varies across Ghidra versions and optional loaders.
    # For SNES, any nonzero loader attempt also triggers raw 65816 fallback;
    # a missing/changed message must not suppress the documented recovery path.
    if grep -Eq "Import failed|No load spec found|could not successfully load" "$import_log" || { [ "$file_type" = "snes" ] && [ "$import_status" -ne 0 ]; }; then
        if [ "$file_type" = "snes" ]; then
            log_warn "SNES ROM Loader rejected file (possibly non-standard header)."
            log_info "Falling back to raw import with 65816 processor..."
            echo ""

            rm -rf "$PROJECTS_DIR/${project_name}.rep" "$PROJECTS_DIR/${project_name}.gpr"

            local fallback_status=0
            if run_headless_logged "$import_log" fallback \
                "$HEADLESS" \
                "$PROJECTS_DIR" "$project_name" \
                -import "$binary_path" \
                -processor "65816:LE:24:snes" \
                -analysisTimeoutPerFile 300; then
                fallback_status=0
            else
                fallback_status=$?
            fi

            if [ "$fallback_status" -ne 0 ] || grep -Eq "Import failed|No load spec found|could not successfully load" "$import_log"; then
                log_error "Import failed even with raw 65816 fallback (exit status: $fallback_status)."
                rm -f "$import_log"
                if [ "$fallback_status" -ne 0 ]; then
                    return "$fallback_status"
                fi
                return 1
            fi
            log_success "Raw 65816 import + analysis complete."
        else
            log_error "Import failed (headless exit status: $import_status)."
            rm -f "$import_log"
            if [ "$import_status" -ne 0 ]; then
                return "$import_status"
            fi
            return 1
        fi
    elif [ "$import_status" -ne 0 ]; then
        log_error "Headless import + analysis exited with status $import_status."
        rm -f "$import_log"
        return "$import_status"
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
    local output_key="${3:-$binary_name}"
    # Keep each invocation's artifacts separate, even if repeated runs start in the same second.
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)_$_${RANDOM}"
    local file_output_dir="$OUTPUT_DIR/$output_key"
    mkdir -p "$file_output_dir"
    # A SIGKILL or host shutdown can bypass normal cleanup. Since process_binary
    # holds this identity's lock, any existing stage belongs to a dead/failed run.
    local stale_stage
    for stale_stage in "$file_output_dir"/.stage.*; do
        if [ -d "$stale_stage" ]; then
            rm -rf "$stale_stage"
        fi
    done
    local stage_dir
    if ! stage_dir="$(mktemp -d "$file_output_dir/.stage.XXXXXX")"; then
        log_error "Could not create a private report staging directory."
        return 1
    fi
    # Include mktemp's random stage token so completed report names do not clobber
    # an older immutable run even if a clock/PID/random suffix is reused.
    local report_base="$stage_dir/${binary_name}_report_${timestamp}_${stage_dir##*.}"

    log_step "Generating report(s) for: ${BOLD}$binary_name${NC} [Formats: ${BOLD}$FORMAT${NC}]"

    local extra_script_flag=""
    if [ "$FULL_DISASM" = "true" ]; then
        extra_script_flag="--full-disasm"
    fi

    local report_log report_status=0
    report_log="$(mktemp)"
    if run_headless_logged "$report_log" report \
        "$HEADLESS" \
        "$PROJECTS_DIR" "$project_name" \
        -process "$binary_name" \
        -readOnly \
        -noanalysis \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript ExportFullReport.java "$report_base" "$FORMAT" "$extra_script_flag"; then
        report_status=0
    else
        report_status=$?
    fi

    if [ "$report_status" -ne 0 ]; then
        log_error "Ghidra report generation failed with exit status $report_status."
        # Partial exporter output stays inside a private staging directory.
        # Remove it on failure without touching prior reports or latest links.
        rm -rf "$stage_dir"
        rm -f "$report_log"
        return "$report_status"
    fi
    rm -f "$report_log"

    local has_report=false
    for ext in txt json md html sarif yar misp.json; do
        if [ -f "${report_base}.${ext}" ]; then
            has_report=true
            break
        fi
    done

    if [ "$has_report" = true ]; then
        # Nothing is visible in the output directory until the exporter has
        # finished successfully. Rename complete artifacts onto the same
        # filesystem before atomically replacing any report_latest.* links.
        local published_files=()
        for ext in txt json md html sarif yar misp.json; do
            local staged_file="${report_base}.${ext}"
            if [ -f "$staged_file" ]; then
                local final_file="$file_output_dir/$(basename "$staged_file")"
                if [ -e "$final_file" ] || [ -L "$final_file" ]; then
                    for published_file in "${published_files[@]}"; do
                        rm -f "$published_file"
                    done
                    rm -rf "$stage_dir"
                    log_error "Refusing to overwrite an existing immutable report artifact: $(basename "$final_file")"
                    return 1
                fi
                if ! mv "$staged_file" "$final_file"; then
                    for published_file in "${published_files[@]}"; do
                        rm -f "$published_file"
                    done
                    rm -rf "$stage_dir"
                    log_error "Could not publish completed report artifact: $(basename "$staged_file")"
                    return 1
                fi
                published_files+=("$final_file")
            fi
        done
        rm -rf "$stage_dir"
        local txt_report="$file_output_dir/$(basename "${report_base}.txt")"
        local json_report="$file_output_dir/$(basename "${report_base}.json")"
        local latest_publish_status=0

        echo ""
        log_success "Reports generated successfully in: ${BOLD}$file_output_dir${NC}"

        for ext in txt json md html sarif yar misp.json; do
            local f="$file_output_dir/$(basename "${report_base}.${ext}")"
            if [ -f "$f" ]; then
                local sz
                sz="$(du -h "$f" | cut -f1)"
                echo -e "    ${GREEN}●${NC} $(basename "$f")  ${DIM}($sz)${NC}"
                if ! python3 "$SCRIPTS_DIR/atomic_publish.py" symlink "$file_output_dir/report_latest.${ext}" "$(basename "$f")"; then
                    log_error "Could not atomically update report_latest.${ext}; its previous target was retained."
                    latest_publish_status=1
                fi
            fi
        done
        echo -e "    ${CYAN}➜${NC} Latest symlinks updated atomically per format: ${DIM}$file_output_dir/report_latest.*${NC}"

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
        return "$latest_publish_status"
    else
        rm -rf "$stage_dir"
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
        return 1
    fi

    # Analysis requires Ghidra; help and offline utility modes do not.
    check_prereqs

    local binary_name
    binary_name="$(basename "$binary_path")"
    local identity_line
    if ! identity_line="$(python3 "$SCRIPTS_DIR/project_identity.py" identities "$binary_path" "${RUN_FINDCRYPT:-false}" "${GHIDRA_ROOT:-}")"; then
        log_error "Could not derive project/output identity for: $binary_path"
        return 1
    fi
    local project_name output_key
    IFS=$'\t' read -r project_name output_key <<< "$identity_line"
    if [ -z "$project_name" ] || [ -z "$output_key" ]; then
        log_error "Could not derive a safe project/output identity for: $binary_path"
        return 1
    fi

    # Serialize the whole operation for this identity. The lock protects the
    # shared Ghidra project and report_latest.* updates across CLI invocations.
    if ! acquire_output_lock "$output_key"; then
        log_error "Skipping analysis because its report-output lock was not acquired."
        return 1
    fi
    # Preserve lock cleanup even if errexit exits the shell during analysis.
    trap 'release_output_lock' EXIT

    local process_status=0
    if [ -f "$PROJECTS_DIR/${project_name}.gpr" ] && [ "$force_reimport" != "true" ]; then
        log_info "Project already exists: $project_name"
        log_info "Use --reimport to force re-import with fresh analysis."
    else
        if ! import_and_analyze "$binary_path" "$project_name"; then
            log_error "Skipping report generation due to import failure."
            release_output_lock
            trap - EXIT
            return 1
        fi
    fi

    # Call directly so shell errexit behavior remains intact; the EXIT trap
    # releases the lock if report generation terminates the CLI on a failure.
    generate_report "$project_name" "$binary_name" "$output_key"
    process_status=$?
    release_output_lock
    trap - EXIT
    return "$process_status"
}

# Batch process all supported files in ingress/. Any failed item makes the overall command fail.
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
        -o -iname "*.gba" -o -iname "*.psx" \
        -o -iname "*.z64" -o -iname "*.n64" -o -iname "*.v64" \
    \) | sort)

    local total="${#files[@]}"
    if [ "$total" -eq 0 ]; then
        log_warn "No supported binaries found in $INGRESS_DIR"
        log_info "Supported extensions: .bin .sfc .smc .fig .gba .psx .z64 .n64 .v64 .exe .dll .sys .elf .so .o .rom"
        return 0
    fi

    local jobs="${PARALLEL_JOBS:-1}"
    if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
        log_error "Parallel worker count must be a positive integer, got: $jobs"
        return 2
    fi
    if [ "$jobs" -gt "$total" ]; then
        jobs="$total"
    fi

    if [ "$jobs" -gt 1 ]; then
        log_step "Dispatching $total file(s) across ${BOLD}$jobs parallel workers${NC}..."
    else
        log_step "Processing $total file(s) serially..."
    fi

    if run_batch_workers "$jobs" process_binary "${files[@]}"; then
        echo ""
        log_success "Batch processing complete: ${BATCH_SUCCESS_COUNT}/${BATCH_TOTAL_COUNT} succeeded, 0 failed."
        return 0
    else
        local batch_status=$?
        echo ""
        log_error "Batch processing finished: ${BATCH_SUCCESS_COUNT}/${BATCH_TOTAL_COUNT} succeeded, ${BATCH_FAILURE_COUNT} failed."
        return "$batch_status"
    fi
}

# Resolve output paths without guessing when a basename has multiple source identities.
resolve_output_directory() {
    local target="$1"
    if [ -d "$OUTPUT_DIR/$target" ]; then
        printf '%s\n' "$OUTPUT_DIR/$target"
        return 0
    fi
    if [ -d "$target" ]; then
        printf '%s\n' "$target"
        return 0
    fi

    local base safe candidate
    base="$(basename "$target")"
    safe="$(printf '%s' "$base" | tr -cs 'a-zA-Z0-9_' '_' | sed 's/^_*//;s/_*$//')"
    safe="${safe:0:72}"
    if [ -z "$safe" ]; then
        return 1
    fi

    local matches=()
    for candidate in "$OUTPUT_DIR/${safe}_"*; do
        if [ -d "$candidate" ] && [ -f "$candidate/report_latest.json" ]; then
            matches+=("$candidate")
        fi
    done

    if [ "${#matches[@]}" -eq 1 ]; then
        printf '%s\n' "${matches[0]}"
        return 0
    fi
    if [ "${#matches[@]}" -gt 1 ]; then
        log_error "More than one output directory matches '$target'. Use a full output path or a specific output identity."
        return 2
    fi
    return 1
}

resolve_report_path() {
    local target="$1"
    if [ -f "$target" ]; then
        printf '%s\n' "$target"
        return 0
    fi
    local output_dir
    output_dir="$(resolve_output_directory "$target")" || return $?
    if [ -f "$output_dir/report_latest.json" ]; then
        printf '%s\n' "$output_dir/report_latest.json"
        return 0
    fi
    return 1
}

# Compare two reports (JSON format) with standardized semantic findings lifecycle
diff_reports() {
    local r1="$1"
    local r2="$2"

    local resolved_path
    if resolved_path="$(resolve_report_path "$r1")"; then
        r1="$resolved_path"
    fi
    if resolved_path="$(resolve_report_path "$r2")"; then
        r2="$resolved_path"
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
    local bind_host="${GHIDRA_DASHBOARD_HOST:-127.0.0.1}"
    log_step "Starting ghidra-report dashboard (bind ${bind_host}:${port})..."
    log_info "Local browser URL: ${BOLD}http://localhost:${port}/${NC}"
    if [ "$bind_host" != "127.0.0.1" ] && [ "$bind_host" != "::1" ]; then
        log_warn "Dashboard has no authentication; expose non-loopback binds only on a trusted, protected network."
    fi
    log_info "Press Ctrl+C to stop."
    echo ""
    if [ -f "$SCRIPTS_DIR/dashboard.py" ]; then
        python3 "$SCRIPTS_DIR/dashboard.py" "$port"
    else
        python3 -m http.server "$port" --bind "$bind_host" --directory "$SCRIPT_DIR"
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
    if [ ! -f "$rep" ]; then
        local resolved_path
        if resolved_path="$(resolve_report_path "$rep")"; then
            rep="$resolved_path"
        fi
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
    if [ ! -f "$rep" ]; then
        local resolved_path
        if resolved_path="$(resolve_report_path "$rep")"; then
            rep="$resolved_path"
        fi
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
