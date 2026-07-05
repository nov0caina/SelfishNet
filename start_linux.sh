#!/bin/bash
# ═══════════════════════════════════════════════════════
#  SelfishNet — Linux Launcher
#  Enables IP forwarding and runs with sudo
# ═══════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/SelfishNet"
BINARY="$PROJECT_DIR/bin/Release/net8.0/SelfishNet"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║     SelfishNet — Linux Launcher      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Check if built ──
if [ ! -f "$BINARY" ] && [ ! -f "$BINARY.dll" ]; then
    echo -e "${RED}[ERROR] SelfishNet not built. Run ./install_linux.sh first.${NC}"
    exit 1
fi

# ── Check for root ──
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] SelfishNet requires root privileges for network access.${NC}"
    echo -e "${YELLOW}    Relaunching with sudo...${NC}"
    echo ""
    exec sudo bash "$0" "$@"
fi

# ── Enable IP forwarding (required for MITM) ──
echo -e "${YELLOW}[1/2] Enabling IP forwarding...${NC}"
CURRENT_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
echo -e "${GREEN}[✓] IP forwarding enabled.${NC}"

# ── Launch ──
echo -e "${YELLOW}[2/2] Launching SelfishNet...${NC}"
echo ""

cd "$PROJECT_DIR"
dotnet run --configuration Release --no-build
EXIT_CODE=$?

# ── Restore IP forwarding to previous state ──
sysctl -w net.ipv4.ip_forward=$CURRENT_FWD > /dev/null 2>&1
echo -e "${GREEN}[✓] IP forwarding restored to previous state ($CURRENT_FWD).${NC}"

exit $EXIT_CODE
