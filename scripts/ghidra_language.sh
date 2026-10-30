#!/usr/bin/env bash
# Check whether an installed Ghidra distribution or extension provides a language ID.
ghidra_language_available() {
    local language_id="${1:-}"
    if [[ -z "$language_id" ]]; then
        return 2
    fi

    local search_roots=()
    if [[ -n "${GHIDRA_ROOT:-}" && -d "$GHIDRA_ROOT" ]]; then
        search_roots+=("$GHIDRA_ROOT")
    fi
    local extension_root="${GHIDRA_EXTENSION_ROOT:-${HOME:-}/.config/ghidra}"
    if [[ -n "$extension_root" && -d "$extension_root" ]]; then
        search_roots+=("$extension_root")
    fi
    (("${#search_roots[@]}" > 0)) || return 1

    find -L "${search_roots[@]}" -type f -name '*.ldefs' \
        -exec grep -Fq -- "id=\"$language_id\"" {} \; -print -quit 2>/dev/null |
        grep -q .
}
