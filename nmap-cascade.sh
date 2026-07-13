#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ==================== CONFIG ====================
MIN_RATE="${MIN_RATE:-750}"
MAX_RETRIES="${MAX_RETRIES:-2}"

# ==================== COLORS ====================
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    MAGENTA=''
    CYAN=''
    BOLD=''
    NC=''
fi

# ==================== HELPERS ====================
die() {
    echo -e "${RED}[!] $*${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[*] $*${NC}"
}

info() {
    echo -e "${CYAN}[*] $*${NC}"
}

ok() {
    echo -e "${GREEN}[✓] $*${NC}"
}

section() {
    local title="$1"

    echo -e "${MAGENTA}${BOLD}"
    echo "═══════════════════════════════════════════════════════"
    echo "  ${title}"
    echo "═══════════════════════════════════════════════════════"
    echo -e "${NC}"
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
}

prompt_required() {
    local prompt="$1"
    local value

    read -r -p "$prompt" value
    [[ -n "$value" ]] || die "This field is mandatory."

    printf '%s' "$value"
}

sanitize_name() {
    local raw="$1"
    local sanitized

    sanitized="$(printf '%s' "$raw" | sed 's/[^[:alnum:]._-]/_/g; s/^_*//; s/_*$//')"

    [[ -n "$sanitized" ]] || sanitized="scan"

    printf '%s' "$sanitized"
}

count_ports() {
    local ports="$1"

    if [[ -z "$ports" ]]; then
        printf '0'
        return
    fi

    local without_commas="${ports//,/}"
    printf '%d' "$(( ${#ports} - ${#without_commas} + 1 ))"
}

extract_open_ports() {
    local gnmap_file="$1"
    local normal_file="$2"
    local ports=""

    # Preferred: grepable nmap output
    if [[ -s "$gnmap_file" ]]; then
        ports="$(
            awk '
                /Ports:/ {
                    sub(/^.*Ports: /, "")
                    n = split($0, entries, ",")
                    for (i = 1; i <= n; i++) {
                        gsub(/^ +| +$/, "", entries[i])
                        split(entries[i], f, "/")
                        if (f[2] == "open" && f[3] == "tcp") {
                            print f[1]
                        }
                    }
                }
            ' "$gnmap_file" | sort -n -u | paste -sd, -
        )"
    fi

    # Fallback: normal nmap output
    if [[ -z "$ports" && -s "$normal_file" ]]; then
        warn "Trying fallback port extraction from normal output..."

        ports="$(
            awk '
                $1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {
                    sub("/tcp", "", $1)
                    print $1
                }
            ' "$normal_file" | sort -n -u | paste -sd, -
        )"
    fi

    printf '%s' "$ports"
}

run_nmap_phase() {
    local phase_title="$1"
    local output_base="$2"

    shift 2

    section "$phase_title"

    local cmd=(
        nmap
        "$@"
        "-${TIMING}"
        -vv
        -oN "${output_base}.txt"
        -oX "${output_base}.xml"
        -oG "${output_base}.gnmap"
        "$TARGET"
    )

    # Join args with spaces explicitly: global IFS starts with newline,
    # so "${cmd[*]}" would otherwise print each arg on its own line.
    info "Running: $(IFS=' '; printf '%s' "${cmd[*]}")"

    if ! "${cmd[@]}"; then
        die "${phase_title} failed."
    fi

    ok "${phase_title} complete."
    ok "Output: ${output_base}.{txt,xml,gnmap}"
    echo
}

write_summary() {
    local summary_file="${OUTPUT_DIR}/SUMMARY.txt"

    info "Generating quick summary..."

    {
        echo "═══ Quick Service Summary ═══"
        echo "Scan: $SCAN_NAME"
        echo "Target: $TARGET"
        echo "Date: $(date)"
        echo "Timing: $TIMING"
        echo "Total Open Ports: $PORT_COUNT"
        echo
        echo "Open Ports: $OPEN_PORTS"
        echo
        echo "═══ Detailed Results ═══"

        if [[ -s "${PHASE2_OUTPUT}.txt" ]]; then
            awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open"' "${PHASE2_OUTPUT}.txt"
        fi
    } > "$summary_file"

    ok "Summary saved: ${summary_file}"
}

# ==================== PRE-FLIGHT ====================
require_command nmap
require_command awk
require_command sort
require_command paste
require_command sed

trap 'die "Unexpected error near line ${LINENO}."' ERR

# ==================== BANNER ====================
echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║         3-PHASE NMAP SCANNER v1.2                     ║"
echo "║         Advanced Port Discovery & Analysis            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Root-aware scan type
if [[ "${EUID}" -eq 0 ]]; then
    TCP_DISCOVERY_SCAN=(-sS)
    # OS detection (-O) and traceroute require raw sockets (root only).
    PHASE3_PRIV=(-O --traceroute)
    info "Root privileges detected. Using SYN scan: -sS"
else
    TCP_DISCOVERY_SCAN=(-sT)
    PHASE3_PRIV=()
    warn "Not running as root. Falling back to TCP connect scan: -sT"
    warn "OS detection and traceroute (Phase 3) will be skipped without root."
    warn "For best performance and stealth, run as root to use SYN scan."
fi

# ==================== INPUT ====================
echo -e "${YELLOW}${BOLD}[*] Enter scan name mandatory:${NC}"
SCAN_NAME_RAW="$(prompt_required "Scan Name: ")"
SCAN_NAME="$(sanitize_name "$SCAN_NAME_RAW")"

echo -e "\n${YELLOW}${BOLD}[*] Select timing template mandatory:${NC}"
echo -e "${CYAN}  T0 - Paranoid very slow, IDS evasion${NC}"
echo -e "${CYAN}  T1 - Sneaky slow, IDS evasion${NC}"
echo -e "${CYAN}  T2 - Polite slow, less bandwidth${NC}"
echo -e "${CYAN}  T3 - Normal default, balanced${NC}"
echo -e "${CYAN}  T4 - Aggressive fast, assumes good network${NC}"
echo -e "${CYAN}  T5 - Insane very fast, may miss ports${NC}"

TIMING="$(prompt_required "Timing T0-T5: ")"

if [[ ! "$TIMING" =~ ^[Tt][0-5]$ ]]; then
    die "Invalid timing template. Use T0-T5."
fi

TIMING="${TIMING^^}"

echo -e "\n${YELLOW}${BOLD}[*] Enter target IP, hostname, or CIDR:${NC}"
TARGET="$(prompt_required "Target: ")"

# ==================== OUTPUT SETUP ====================
OUTPUT_DIR="nmap_${SCAN_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

PHASE1_NAME="${SCAN_NAME}_phase-1"
PHASE2_NAME="${SCAN_NAME}_phase-2"
PHASE3_NAME="${SCAN_NAME}_phase-3"

PHASE1_OUTPUT="${OUTPUT_DIR}/${PHASE1_NAME}"
PHASE2_OUTPUT="${OUTPUT_DIR}/${PHASE2_NAME}"
PHASE3_OUTPUT="${OUTPUT_DIR}/${PHASE3_NAME}"

echo -e "\n${GREEN}[✓] Configuration:${NC}"
echo -e "    Scan Name: ${BOLD}${SCAN_NAME}${NC}"
echo -e "    Timing: ${BOLD}${TIMING}${NC}"
echo -e "    Target: ${BOLD}${TARGET}${NC}"
echo -e "    Output Dir: ${BOLD}${OUTPUT_DIR}${NC}"
echo -e "    Discovery Scan: ${BOLD}${TCP_DISCOVERY_SCAN[*]}${NC}"
echo

# ==================== PHASE 1 ====================
info "Phase 1 will scan all TCP ports 1-65535."
info "Using --open to reduce output noise and speed up parsing."

run_nmap_phase \
    "PHASE 1: QUICK PORT DISCOVERY" \
    "$PHASE1_OUTPUT" \
    -p- \
    "${TCP_DISCOVERY_SCAN[@]}" \
    -Pn \
    -n \
    --open \
    --min-rate "$MIN_RATE" \
    --max-retries "$MAX_RETRIES"

OPEN_PORTS="$(extract_open_ports "${PHASE1_OUTPUT}.gnmap" "${PHASE1_OUTPUT}.txt")"

if [[ -z "$OPEN_PORTS" ]]; then
    echo -e "${YELLOW}[*] Check output files for details:${NC}"
    echo -e "    ${PHASE1_OUTPUT}.txt"
    echo -e "    ${PHASE1_OUTPUT}.gnmap"
    die "No open TCP ports found. Exiting."
fi

PORT_COUNT="$(count_ports "$OPEN_PORTS")"

ok "${BOLD}${PORT_COUNT}${NC}${GREEN} open TCP ports discovered:"
echo -e "${BOLD}${OPEN_PORTS}${NC}\n"

# ==================== PHASE 2 ====================
info "Phase 2 will run service/version detection and default scripts on discovered ports."

run_nmap_phase \
    "PHASE 2: SERVICE ENUMERATION" \
    "$PHASE2_OUTPUT" \
    -p "$OPEN_PORTS" \
    "${TCP_DISCOVERY_SCAN[@]}" \
    -sV \
    --version-all \
    -sC \
    -Pn \
    -n

# ==================== PHASE 3 ====================
info "Phase 3 will run vuln NSE category (plus OS/traceroute if root) on discovered ports."

# Default NSE scripts already ran in Phase 2 (-sC); Phase 3 adds only the
# vuln category. -sV stays because vuln scripts match on version data
# detected within the same nmap invocation (phases are separate processes).
run_nmap_phase \
    "PHASE 3: BEHAVIORAL ANALYSIS" \
    "$PHASE3_OUTPUT" \
    -p "$OPEN_PORTS" \
    "${TCP_DISCOVERY_SCAN[@]}" \
    -sV \
    ${PHASE3_PRIV[@]+"${PHASE3_PRIV[@]}"} \
    --script vuln \
    -Pn \
    -n

# ==================== SUMMARY ====================
section "SCAN COMPLETE"

echo -e "${CYAN}[✓] Scan Summary:${NC}"
echo -e "    Target: ${BOLD}${TARGET}${NC}"
echo -e "    Scan Name: ${BOLD}${SCAN_NAME}${NC}"
echo -e "    Timing: ${BOLD}${TIMING}${NC}"
echo -e "    Total Ports: ${BOLD}${PORT_COUNT}${NC}"
echo -e "    Open Ports: ${BOLD}${OPEN_PORTS}${NC}"
echo -e "    Output Directory: ${BOLD}${OUTPUT_DIR}${NC}"
echo

echo -e "${YELLOW}[*] All results saved in: ${BOLD}${OUTPUT_DIR}/${NC}"
echo -e "${YELLOW}[*] Phase 1: Port Discovery      -> ${PHASE1_NAME}.*${NC}"
echo -e "${YELLOW}[*] Phase 2: Service Enumeration -> ${PHASE2_NAME}.*${NC}"
echo -e "${YELLOW}[*] Phase 3: Behavioral Analysis -> ${PHASE3_NAME}.*${NC}"
echo

write_summary

echo
echo -e "${GREEN}${BOLD}Happy Hunting!${NC}"
