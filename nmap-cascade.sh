#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELPER="${SCRIPT_DIR}/cascade_report.py"
NSE_SELECTION='(default or vuln) and safe and not external and not intrusive'
CHILD_PID=''
ACTIVE_PHASE=''
ACTIVE_OUTPUT=''

die() { printf '[!] %s\n' "$*" >&2; exit 1; }
info() { printf '[*] %s\n' "$*" >&2; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

prompt_required() {
    local value
    read -r -p "$1" value || die 'Input ended unexpectedly.'
    [[ -n "$value" ]] || die 'This field is mandatory.'
    printf '%s' "$value"
}

sanitize_name() {
    local sanitized
    sanitized="$(printf '%s' "$1" | sed 's/[^[:alnum:]._-]/_/g; s/^_*//; s/_*$//')"
    printf '%s' "${sanitized:-scan}"
}

event() { python3 "$HELPER" event "$OUTPUT_DIR" "$@"; }

finish() {
    local code=$?
    trap - EXIT INT TERM
    # Finalization must not hide the original Nmap/signal exit status.
    if python3 "$HELPER" report "$OUTPUT_DIR" "$code"; then
        info "Report: $OUTPUT_DIR/SUMMARY.txt"
        info "HTML report: $OUTPUT_DIR/REPORT.html"
        if [[ "$code" -eq 0 ]]; then info 'SCAN COMPLETE'; fi
    else
        info "Report generation failed; raw evidence remains in $OUTPUT_DIR."
        if [[ "$code" -eq 0 ]]; then code=1; fi
    fi
    exit "$code"
}

interrupt() {
    local code="$1"
    trap '' INT TERM
    if [[ -n "$CHILD_PID" ]]; then
        kill -TERM "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
    fi
    if [[ -n "$ACTIVE_PHASE" ]]; then
        event "$ACTIVE_PHASE" interrupted "$code" "${ACTIVE_OUTPUT}.xml" || true
    fi
    exit "$code"
}

run_command() {
    local phase="$1" base="$2" validator="$3" code=0
    local stdout_fd stderr_fd stdout_pid stderr_pid log_error=0 display=/dev/stdout
    shift 3
    ACTIVE_PHASE="$phase"
    ACTIVE_OUTPUT="$base"
    event "$phase" started '' "${base}.xml" "$@"
    printf '[*] Running:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    # Keep the full script help in its log, without flooding live progress.
    if [[ "$phase" == script-selection ]]; then display=/dev/null; fi
    exec {stdout_fd}> >(tee "${base}.stdout.log" > "$display")
    stdout_pid=$!
    exec {stderr_fd}> >(tee "${base}.stderr.log" >&2)
    stderr_pid=$!
    "$@" >&"$stdout_fd" 2>&"$stderr_fd" &
    CHILD_PID=$!
    exec {stdout_fd}>&- {stderr_fd}>&-
    wait "$CHILD_PID" || code=$?
    CHILD_PID=''
    wait "$stdout_pid" || log_error=1
    wait "$stderr_pid" || log_error=1
    if [[ "$log_error" -ne 0 ]]; then
        info "$phase log capture failed."
        if [[ "$code" -eq 0 ]]; then code=74; fi
    fi
    if [[ "$code" -eq 0 ]]; then
        python3 "$HELPER" "$validator" "${base}.xml" || code=65
    fi
    if [[ "$code" -ne 0 ]]; then
        event "$phase" failed "$code" "${base}.xml"
        info "$phase failed (exit $code)."
        exit "$code"
    fi
    event "$phase" completed 0 "${base}.xml"
    ACTIVE_PHASE=''
    info "$phase complete."
}

run_nmap_phase() {
    local phase="$1" base="$2" target="$3"
    shift 3
    local cmd=(nmap "$@" "${TCP_SCAN[@]}" "-${TIMING}" -Pn -n -vv --reason
        --stats-every 10s -oN "${base}.txt" -oX "${base}.xml" -oG "${base}.gnmap" "$target")
    run_command "$phase" "$base" check "${cmd[@]}"
}

for command in nmap python3 sed mktemp tee; do require_command "$command"; done
[[ -f "$HELPER" ]] || die "Missing helper: $HELPER"

SCAN_NAME_RAW="$(prompt_required 'Scan Name: ')"
SCAN_NAME="$(sanitize_name "$SCAN_NAME_RAW")"
read -r -p 'Timing T0-T5 [T3]: ' TIMING || die 'Input ended unexpectedly.'
TIMING="${TIMING:-T3}"
[[ "$TIMING" =~ ^[Tt][0-5]$ ]] || die 'Invalid timing template. Use T0-T5.'
TIMING="${TIMING^^}"
TARGET="$(prompt_required 'Target IPv4, hostname, or IPv4 CIDR: ')"
# Only validated hostnames may enter NSE's script-argument syntax.
HOSTNAME_CONTEXT="$(python3 "$HELPER" target "$TARGET")"

DISCOVERY_OPTIONS=()
if [[ -n "${MIN_RATE+x}" ]]; then
    python3 "$HELPER" rate "$MIN_RATE"
    DISCOVERY_OPTIONS+=(--min-rate "$MIN_RATE")
fi
if [[ -n "${MAX_RETRIES+x}" ]]; then
    [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]] || die 'MAX_RETRIES must be a nonnegative integer.'
    DISCOVERY_OPTIONS+=(--max-retries "$MAX_RETRIES")
fi

TCP_SCAN=(-sT)
ENRICHMENT_OPTIONS=()
if [[ "$EUID" -eq 0 ]]; then
    TCP_SCAN=(-sS)
    DISCOVERY_OPTIONS+=(-O --osscan-limit)
    ENRICHMENT_OPTIONS+=(--traceroute)
else
    info 'Using TCP connect scans; OS detection and traceroute skipped without root.'
fi
if [[ -n "$HOSTNAME_CONTEXT" ]]; then
    ENRICHMENT_OPTIONS+=(--script-args "http.host=${HOSTNAME_CONTEXT},tls.servername=${HOSTNAME_CONTEXT}")
fi

OUTPUT_DIR="$(mktemp -d "nmap_${SCAN_NAME}_$(date +%Y%m%d_%H%M%S)_XXXXXX")"
python3 "$HELPER" init "$OUTPUT_DIR" "$SCAN_NAME" "$TARGET" "$TIMING" "$EUID" "$NSE_SELECTION"
trap finish EXIT
trap 'interrupt 130' INT
trap 'interrupt 143' TERM
nmap --version > "$OUTPUT_DIR/nmap-version.txt"

# Record the installed scripts selected by this policy, not a presumed list.
run_command script-selection "$OUTPUT_DIR/script-selection" check-selection \
    nmap --script-help "$NSE_SELECTION" -oX "$OUTPUT_DIR/script-selection.xml"

info 'PHASE 1: full TCP discovery and OS detection where supported.'
run_nmap_phase discovery "$OUTPUT_DIR/${SCAN_NAME}_phase-1" "$TARGET" \
    -p- "${DISCOVERY_OPTIONS[@]}"
python3 "$HELPER" jobs "$OUTPUT_DIR/${SCAN_NAME}_phase-1.xml" > "$OUTPUT_DIR/jobs.tsv"

info 'PHASE 2: one combined service/NSE analysis per discovered host.'
if [[ ! -s "$OUTPUT_DIR/jobs.tsv" ]]; then
    event enrichment skipped '' ''
    info 'No open TCP ports observed; enrichment skipped.'
fi
while IFS=$'\t' read -r address ports; do
    run_nmap_phase "enrichment:$address" "$OUTPUT_DIR/${SCAN_NAME}_phase-2_${address}" "$address" \
        -p "$ports" -sV --version-all --script "$NSE_SELECTION" "${ENRICHMENT_OPTIONS[@]}"
done < "$OUTPUT_DIR/jobs.tsv"

info 'PHASE 3: reconciling observations and writing reports.'
