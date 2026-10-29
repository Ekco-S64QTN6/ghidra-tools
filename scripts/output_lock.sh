#!/usr/bin/env bash
# Cross-process per-output identity lock. This keeps import, analysis, report
# generation, and report_latest.* updates for one identity serialized.
# Distinct identities can still use the parallel batch worker pool.

OUTPUT_LOCK_PID=""
OUTPUT_LOCK_READ_FD=""
OUTPUT_LOCK_WRITE_FD=""

acquire_output_lock() {
    local output_key="$1"
    local timeout="${GHIDRA_OUTPUT_LOCK_TIMEOUT-900}"
    if [[ ! "$output_key" =~ ^[A-Za-z0-9_]+$ ]]; then
        log_error "Refusing unsafe report-output lock identity: $output_key"
        return 2
    fi
    if [[ ! "$timeout" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$timeout" -gt 86400 ]; then
        log_error "GHIDRA_OUTPUT_LOCK_TIMEOUT must be an integer between 1 and 86400 seconds."
        return 2
    fi
    if ! mkdir -p "$OUTPUT_DIR/.locks"; then
        log_error "Could not create report-output lock directory."
        return 1
    fi

    local lock_path="$OUTPUT_DIR/.locks/$output_key.lock"
    local response=""
    local read_timeout=$((timeout + 5))

    coproc GHIDRA_OUTPUT_LOCK_PROCESS {
        python3 "$SCRIPTS_DIR/output_lock.py" "$lock_path" "$timeout"
    }
    OUTPUT_LOCK_PID="${GHIDRA_OUTPUT_LOCK_PROCESS_PID-}"
    OUTPUT_LOCK_READ_FD="${GHIDRA_OUTPUT_LOCK_PROCESS[0]-}"
    OUTPUT_LOCK_WRITE_FD="${GHIDRA_OUTPUT_LOCK_PROCESS[1]-}"

    if [[ -z "$OUTPUT_LOCK_PID" || -z "$OUTPUT_LOCK_READ_FD" || -z "$OUTPUT_LOCK_WRITE_FD" ]]; then
        release_output_lock
        log_error "Could not start the report-output lock helper."
        return 1
    fi

    if ! IFS= read -r -t "$read_timeout" -u "$OUTPUT_LOCK_READ_FD" response; then
        kill "$OUTPUT_LOCK_PID" 2>/dev/null || true
        release_output_lock
        log_error "Timed out waiting for report-output lock: $output_key"
        return 1
    fi
    if [[ "$response" != "LOCKED" ]]; then
        release_output_lock
        log_error "Could not acquire report-output lock for identity: $output_key ($response)"
        return 1
    fi
    return 0
}

release_output_lock() {
    local lock_pid="${OUTPUT_LOCK_PID-}"
    local read_fd="${OUTPUT_LOCK_READ_FD-}"
    local write_fd="${OUTPUT_LOCK_WRITE_FD-}"

    # These descriptors are numeric values created by Bash's coproc facility.
    # Closing the write end sends EOF to the helper, which releases its OS lock.
    if [[ "$write_fd" =~ ^[0-9]+$ ]]; then
        eval "exec $write_fd>&-" 2>/dev/null || true
    fi
    if [[ "$read_fd" =~ ^[0-9]+$ ]]; then
        eval "exec $read_fd<&-" 2>/dev/null || true
    fi
    if [[ "$lock_pid" =~ ^[0-9]+$ ]]; then
        wait "$lock_pid" 2>/dev/null || true
    fi

    OUTPUT_LOCK_PID=""
    OUTPUT_LOCK_READ_FD=""
    OUTPUT_LOCK_WRITE_FD=""
}
