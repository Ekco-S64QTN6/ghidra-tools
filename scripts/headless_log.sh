#!/usr/bin/env bash
# Run a command through tee while preserving its exit status.
# Call this function inside an if/else so callers can handle failures explicitly.

run_headless_logged() {
    if [[ $# -lt 3 ]]; then
        printf '[ERROR] run_headless_logged requires a log path, filter mode, and command.\n' >&2
        return 2
    fi

    local log_path="$1"
    local filter_mode="$2"
    shift 2

    case "$filter_mode" in
        import|fallback) ;;
        *)
            printf '[ERROR] Unknown headless log filter mode: %s\n' "$filter_mode" >&2
            return 2
            ;;
    esac

    # Do not depend on caller options: a failing analyzer must not be hidden by tee.
    set -o pipefail

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
        esac

        if [[ "$show_line" == true ]]; then
            printf '    %s\n' "$line"
        fi
    done
}
