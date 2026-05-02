#!/bin/bash
# ================================
# INSTALLER - MC Real IP Recon Tool
# Run: chmod +x install.sh && sudo ./install.sh
# ================================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════╗"
echo "║   MC Recon Tool - Dependency Installer   ║"
echo "╚════════════════════════╝"
echo -e "${NC}"

apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv dnsutils nmap curl jq whois \
    traceroute masscan netcat-openbsd openssl git libssl-dev net-tools

python3 -m venv /opt/mcrecon_env
source /opt/mcrecon_env/bin/activate

pip install --upgrade pip
pip install dnspython requests shodan censys python-nmap cryptography \
    mcstatus aiohttp beautifulsoup4 colorama tabulate ipwhois scapy

echo -e "${GREEN}[✓] All dependencies installed successfully!${NC}"
echo -e "${CYAN}[i] Activate env: source /opt/mcrecon_env/bin/activate${NC}"
