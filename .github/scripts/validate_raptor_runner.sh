#!/usr/bin/env bash
#
# Validate that an ephemeral self-hosted RAPTOR runner has the tools needed by
# the CI/security plan. The checks are read-only with respect to the repository.

set -euo pipefail

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

first_non_empty_line() {
    local line

    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            printf '%s\n' "$line"
            return 0
        fi
    done <<< "$1"

    return 0
}

tool_path() {
    command -v "$1" 2>/dev/null || true
}

require_tool() {
    local name="$1"
    local path

    path="$(tool_path "$name")"
    if [[ -z "$path" ]]; then
        die "missing required tool: ${name}. Install it or add it to PATH."
    fi

    printf '%s\n' "$path"
}

print_ok() {
    local label="$1"
    local path="$2"
    local version="$3"

    if [[ -n "$version" ]]; then
        printf 'OK: %s found at %s (%s)\n' "$label" "$path" "$version"
    else
        printf 'OK: %s found at %s\n' "$label" "$path"
    fi
}

die_probe_failed() {
    local label="$1"
    local path="$2"
    local probe="$3"
    local output="$4"
    local detail

    detail="$(first_non_empty_line "$output")"
    if [[ -z "$detail" ]]; then
        detail="no output"
    fi

    die "${label} is present at ${path}, but '${probe}' failed: ${detail}"
}

check_version() {
    local label="$1"
    local cmd="$2"
    shift 2

    local path
    local output
    local probe="$cmd"
    local version

    path="$(require_tool "$cmd")"
    if [[ $# -gt 0 ]]; then
        probe="${probe} $*"
    fi

    if ! output="$("$cmd" "$@" 2>&1)"; then
        die_probe_failed "$label" "$path" "$probe" "$output"
    fi

    version="$(first_non_empty_line "$output")"
    print_ok "$label" "$path" "$version"
}

check_docker() {
    local path
    local output
    local version
    local server_version

    path="$(require_tool docker)"
    if ! output="$(docker --version 2>&1)"; then
        die_probe_failed "docker" "$path" "docker --version" "$output"
    fi
    version="$(first_non_empty_line "$output")"
    print_ok "docker" "$path" "$version"

    if ! output="$(docker info --format '{{.ServerVersion}}' 2>&1)"; then
        die_probe_failed "docker CLI" "$path" "docker info" "$output"
    fi
    server_version="$(first_non_empty_line "$output")"
    if [[ -n "$server_version" ]]; then
        printf 'OK: docker daemon reachable (server %s)\n' "$server_version"
    else
        printf 'OK: docker daemon reachable\n'
    fi
}

check_sudo() {
    local path
    local output
    local version

    path="$(require_tool sudo)"
    if ! output="$(sudo -V 2>&1)"; then
        die_probe_failed "sudo" "$path" "sudo -V" "$output"
    fi
    version="$(first_non_empty_line "$output")"
    print_ok "sudo" "$path" "$version"

    if ! output="$(sudo -n true 2>&1)"; then
        die_probe_failed "sudo" "$path" "sudo -n true" "$output"
    fi
    printf 'OK: sudo non-interactive check passed\n'
}

check_afl() {
    local cmd
    local path
    local output
    local version

    for cmd in afl-fuzz afl++; do
        path="$(tool_path "$cmd")"
        if [[ -n "$path" ]]; then
            if [[ "$cmd" == "afl++" ]]; then
                if ! output="$("$cmd" --version 2>&1)"; then
                    output="$("$cmd" -h 2>&1 || true)"
                fi
            else
                output="$("$cmd" -h 2>&1 || true)"
            fi

            version="$(first_non_empty_line "$output")"
            print_ok "AFL fuzzer (${cmd})" "$path" "$version"
            return 0
        fi
    done

    die "missing required AFL fuzzer: expected afl-fuzz or afl++ in PATH."
}

check_rr_if_required() {
    local arch

    arch="$(uname -m)"
    printf 'INFO: runner architecture is %s\n' "$arch"

    case "$arch" in
        x86_64 | amd64)
            check_version "rr" rr --version
            ;;
        *)
            printf 'SKIP: rr is not required on architecture %s\n' "$arch"
            ;;
    esac
}

main() {
    printf 'Validating RAPTOR ephemeral runner prerequisites...\n'

    check_docker
    check_sudo
    check_version "codeql" codeql version
    check_version "semgrep" semgrep --version
    check_afl
    check_version "gdb" gdb --version
    check_rr_if_required
    check_version "python3" python3 --version
    check_version "node" node --version
    check_version "git" git --version
    check_version "curl" curl --version

    printf 'OK: RAPTOR runner prerequisite validation completed.\n'
}

main "$@"
