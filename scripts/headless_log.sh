#!/usr/bin/env bash
# Run a command through tee while preserving the complete pipeline exit status.
# The caller should use this function in an if/else when running under set -e.

run_headless_logged() {
    if [[ $# -lt 3 ]]; then
        printf '[ERROR] run_headless_logged requires a log path, filter mode, and command.\n' >&2
        return 2
    fi

    local log_path="$1"
    local filter_mode="$2"
    shift 2

    "$@" 2>&1 | tee "$log_path" | while IFS= read -r line; do
        local show_line=false
        case "$filter_mode" in
            import)
                if printf '%s\n' "$line" | grep -qE 'INFO.*[Ii]mport|INFO.*[Aa]nalys|INFO.*Loaded|ERROR|WARN'; then
                    show_line=true
                fi
                ;;
            fallback)
                if printf '%s\n' "$line" | grep -qE 'INFO.*[Ii]mport|INFO.*[Aa]nalys|ERROR|WARN'; then
                    show_line=true
                fi
                ;;
            *)
                printf '[ERROR] Unknown headless log filter mode: %s\n' "$filter_mode" >&2
                exit 2
                ;;
        esac

        if [[ "$show_line" == true ]]; then
            printf '    %s\n' "$line"
        fi
    done
}
