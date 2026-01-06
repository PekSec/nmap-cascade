#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║         3-PHASE NMAP SCANNER v1.0                     ║"
echo "║         Advanced Port Discovery & Analysis            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script should be run as root for best results${NC}"
   echo -e "${YELLOW}[*] Some features may not work without root privileges${NC}"
fi

# Mandatory: Get scan name
echo -e "${YELLOW}${BOLD}[*] Enter scan name (mandatory):${NC}"
read -p "Scan Name: " SCAN_NAME

if [ -z "$SCAN_NAME" ]; then
    echo -e "${RED}[!] Error: Scan name is mandatory!${NC}"
    exit 1
fi

# Mandatory: Get timing template
echo -e "\n${YELLOW}${BOLD}[*] Select timing template (mandatory):${NC}"
echo -e "${CYAN}  T0 - Paranoid (Very slow, IDS evasion)${NC}"
echo -e "${CYAN}  T1 - Sneaky (Slow, IDS evasion)${NC}"
echo -e "${CYAN}  T2 - Polite (Slow, less bandwidth)${NC}"
echo -e "${CYAN}  T3 - Normal (Default, balanced)${NC}"
echo -e "${CYAN}  T4 - Aggressive (Fast, assumes good network)${NC}"
echo -e "${CYAN}  T5 - Insane (Very fast, may miss ports)${NC}"

read -p "Timing (T0-T5): " TIMING

if [[ ! "$TIMING" =~ ^[Tt][0-5]$ ]]; then
    echo -e "${RED}[!] Error: Invalid timing template! Use T0-T5${NC}"
    exit 1
fi

TIMING=$(echo "$TIMING" | tr '[:lower:]' '[:upper:]')

# Get target
echo -e "\n${YELLOW}${BOLD}[*] Enter target IP or hostname:${NC}"
read -p "Target: " TARGET

if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Error: Target is required!${NC}"
    exit 1
fi

# Create output directory
OUTPUT_DIR="nmap_${SCAN_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo -e "\n${GREEN}[✓] Configuration:${NC}"
echo -e "    Scan Name: ${BOLD}$SCAN_NAME${NC}"
echo -e "    Timing: ${BOLD}$TIMING${NC}"
echo -e "    Target: ${BOLD}$TARGET${NC}"
echo -e "    Output Dir: ${BOLD}$OUTPUT_DIR${NC}"
echo ""

# ==================== PHASE 1: QUICK PORT DISCOVERY ====================
PHASE1_NAME="${SCAN_NAME}_phase-1"
PHASE1_OUTPUT="${OUTPUT_DIR}/${PHASE1_NAME}"

echo -e "${MAGENTA}${BOLD}"
echo "═══════════════════════════════════════════════════════"
echo "  PHASE 1: QUICK PORT DISCOVERY"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${CYAN}[*] Scanning all TCP ports (1-65535)...${NC}"
echo -e "${CYAN}[*] Using SYN scan for speed and stealth${NC}"

nmap -p- -sS -Pn -n --min-rate=1000 --max-retries=1 \
    -$TIMING -vv \
    -oN "${PHASE1_OUTPUT}.txt" \
    -oX "${PHASE1_OUTPUT}.xml" \
    -oG "${PHASE1_OUTPUT}.gnmap" \
    $TARGET

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Phase 1 failed!${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Phase 1 complete!${NC}"
echo -e "${GREEN}[✓] Output: ${PHASE1_OUTPUT}.*${NC}\n"

# Extract open ports
OPEN_PORTS=$(grep "^[0-9]" "${PHASE1_OUTPUT}.gnmap" | grep "/open/" | cut -d' ' -f2 | grep -o "[0-9]*" | sort -nu | tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
    echo -e "${RED}[!] No open ports found! Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Open ports discovered: ${BOLD}$OPEN_PORTS${NC}\n"
sleep 2

# ==================== PHASE 2: SERVICE ENUMERATION ====================
PHASE2_NAME="${SCAN_NAME}_phase-2"
PHASE2_OUTPUT="${OUTPUT_DIR}/${PHASE2_NAME}"

echo -e "${MAGENTA}${BOLD}"
echo "═══════════════════════════════════════════════════════"
echo "  PHASE 2: SERVICE ENUMERATION"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${CYAN}[*] Performing service version detection on discovered ports...${NC}"
echo -e "${CYAN}[*] Using aggressive version detection (-sV --version-all)${NC}"

nmap -p$OPEN_PORTS -sV --version-all -sC -Pn -n \
    -$TIMING -vv \
    -oN "${PHASE2_OUTPUT}.txt" \
    -oX "${PHASE2_OUTPUT}.xml" \
    -oG "${PHASE2_OUTPUT}.gnmap" \
    $TARGET

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Phase 2 failed!${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Phase 2 complete!${NC}"
echo -e "${GREEN}[✓] Output: ${PHASE2_OUTPUT}.*${NC}\n"
sleep 2

# ==================== PHASE 3: BEHAVIORAL ANALYSIS ====================
PHASE3_NAME="${SCAN_NAME}_phase-3"
PHASE3_OUTPUT="${OUTPUT_DIR}/${PHASE3_NAME}"

echo -e "${MAGENTA}${BOLD}"
echo "═══════════════════════════════════════════════════════"
echo "  PHASE 3: BEHAVIORAL ANALYSIS"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${CYAN}[*] Running advanced scripts and OS detection...${NC}"
echo -e "${CYAN}[*] Using aggressive scanning with traceroute${NC}"

nmap -p$OPEN_PORTS -A -sC --script=default,vuln -Pn -n \
    -$TIMING -vv \
    -oN "${PHASE3_OUTPUT}.txt" \
    -oX "${PHASE3_OUTPUT}.xml" \
    -oG "${PHASE3_OUTPUT}.gnmap" \
    $TARGET

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Phase 3 failed!${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Phase 3 complete!${NC}"
echo -e "${GREEN}[✓] Output: ${PHASE3_OUTPUT}.*${NC}\n"

# ==================== SUMMARY ====================
echo -e "${GREEN}${BOLD}"
echo "═══════════════════════════════════════════════════════"
echo "  SCAN COMPLETE!"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${CYAN}[✓] Scan Summary:${NC}"
echo -e "    Target: ${BOLD}$TARGET${NC}"
echo -e "    Scan Name: ${BOLD}$SCAN_NAME${NC}"
echo -e "    Timing: ${BOLD}$TIMING${NC}"
echo -e "    Open Ports: ${BOLD}$OPEN_PORTS${NC}"
echo -e "    Output Directory: ${BOLD}$OUTPUT_DIR${NC}"
echo ""
echo -e "${YELLOW}[*] All results saved in: ${BOLD}$OUTPUT_DIR${NC}"
echo -e "${YELLOW}[*] Phase 1: Port Discovery${NC}"
echo -e "${YELLOW}[*] Phase 2: Service Enumeration${NC}"
echo -e "${YELLOW}[*] Phase 3: Behavioral Analysis${NC}"
echo ""
echo -e "${GREEN}${BOLD}Happy Hunting! 🎯${NC}"
