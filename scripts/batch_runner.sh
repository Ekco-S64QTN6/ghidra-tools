#!/usr/bin/env bash
# Shared, testable batch worker scheduler for ghidra-report.sh.
# Source this file; call run_batch_workers <max_jobs> <function_name> <args...>.

run_batch_workers() {
    if [[ $# -lt 2 ]]; then
        printf '[ERROR] run_batch_workers requires a worker count, function name, and at least one item.\n' >&2
        return 2
    fi

    local max_jobs="$1"
    local worker="$2"
    shift 2

    if [[ ! "$max_jobs" =~ ^[1-9][0-9]*$ ]]; then
        printf '[ERROR] Batch worker count must be a positive integer, got: %s\n' "$max_jobs" >&2
        return 2
    fi
    if [[ ! "$worker" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || ! declare -F "$worker" >/dev/null 2>&1; then
        printf '[ERROR] Batch worker function is not defined: %s\n' "$worker" >&2
        return 2
    fi

    local total="$#"
    local started=0
    local succeeded=0
    local failed=0

    # Process fixed-size waves so each PID can be waited exactly once while
    # preserving correct failure status on Bash versions without wait -p.
    while [[ $# -gt 0 ]]; do
        local pids=()
        local paths=()
        local batch_count=0

        while [[ $# -gt 0 && "$batch_count" -lt "$max_jobs" ]]; do
            local item="$1"
            shift
            started=$((started + 1))
            batch_count=$((batch_count + 1))
            printf '[BATCH] Item %d/%d: %s\n' "$started" "$total" "$(basename -- "$item")"
            "$worker" "$item" &
            pids+=("$!")
            paths+=("$item")
        done

        local index
        for ((index = 0; index < ${#pids[@]}; index++)); do
            if wait "${pids[$index]}"; then
                succeeded=$((succeeded + 1))
            else
                failed=$((failed + 1))
                printf '[ERROR] Batch worker failed for: %s\n' "${paths[$index]}" >&2
            fi
        done
    done

    BATCH_TOTAL_COUNT="$total"
    BATCH_SUCCESS_COUNT="$succeeded"
    BATCH_FAILURE_COUNT="$failed"

    if [[ "$failed" -eq 0 ]]; then
        return 0
    fi
    return 1
}
