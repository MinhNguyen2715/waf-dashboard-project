#!/bin/bash
# ==============================================================================
# Script Name: setup.sh
# Description: Automated setup script for Nginx, ModSecurity v3, OWASP CRS v4,
#              and FastAPI WAF Dashboard Backend environment.
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status

# Color definitions for output messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Starting WAF Dashboard Environment Setup ===${NC}"

# 1. Update system packages and install necessary dependencies
echo -e "\n${YELLOW}[Step 1/6] Installing system dependencies...${NC}"
sudo apt-get update -y
sudo apt-get install -y nginx libmodsecurity3 modsecurity-crs wget tar python3 python3-venv python3-pip

# 2. Prepare target directories for ModSecurity configurations and rules
echo -e "\n${YELLOW}[Step 2/6] Preparing configuration directories...${NC}"
sudo mkdir -p /etc/nginx/modsec
sudo mkdir -p /etc/nginx/modsecurity-crs/rules

# 3. Download and extract OWASP Core Rule Set (CRS) v4.25.0
echo -e "\n${YELLOW}[Step 3/6] Downloading OWASP CRS v4.25.0...${NC}"
TEMP_DIR=$(mktemp -d)
wget -q https://github.com/coreruleset/coreruleset/releases/download/v4.25.0/coreruleset-4.25.0.tar.gz -O "$TEMP_DIR/crs.tar.gz"
tar -xzf "$TEMP_DIR/crs.tar.gz" -C "$TEMP_DIR"

# Copy rules to system directory and clean up example files to avoid duplicate rule IDs
echo -e "Deploying CRS rules..."
sudo cp -r "$TEMP_DIR/coreruleset-4.25.0/rules/"* /etc/nginx/modsecurity-crs/rules/
sudo rm -f /etc/nginx/modsecurity-crs/rules/*.example
rm -rf "$TEMP_DIR"

# 4. Deploy custom WAF configuration files from repository
echo -e "\n${YELLOW}[Step 4/6] Deploying custom WAF configuration files...${NC}"
if [ -d "waf-configs" ]; then
    echo -e "Copying configuration files from waf-configs/..."
    sudo cp waf-configs/nginx/default.conf /etc/nginx/sites-available/default
    sudo cp waf-configs/modsec/main.conf /etc/nginx/modsec/main.conf
    sudo cp waf-configs/modsec/modsecurity.conf /etc/nginx/modsec/modsecurity.conf
    sudo cp waf-configs/modsec/crs-setup.conf /etc/nginx/modsecurity-crs/crs-setup.conf
else
    echo -e "${RED}[Error] Directory waf-configs/ not found in the current path!${NC}"
    exit 1
fi

# 5. Test Nginx syntax and reload service
echo -e "\n${YELLOW}[Step 5/6] Validating Nginx configuration...${NC}"
if sudo nginx -t; then
    echo -e "${GREEN}Nginx syntax check passed. Reloading Nginx...${NC}"
    sudo systemctl reload nginx
else
    echo -e "${RED}[Error] Nginx syntax check failed! Please review your configurations.${NC}"
    exit 1
fi

# 6. Set up Python Virtual Environment for FastAPI Backend
echo -e "\n${YELLOW}[Step 6/6] Setting up FastAPI Backend virtual environment...${NC}"
if [ -d "backend" ]; then
    cd backend
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        echo -e "Created Python virtual environment in backend/venv."
    fi
    ./venv/bin/pip install --upgrade pip
    if [ -f "requirements.txt" ]; then
        ./venv/bin/pip install -r requirements.txt
        echo -e "${GREEN}Installed Python dependencies from requirements.txt.${NC}"
    fi
    cd ..
else
    echo -e "${RED}[Warning] Directory backend/ not found. Skipping Python setup.${NC}"
fi

echo -e "\n${GREEN}=== WAF Dashboard Environment Setup Completed Successfully! ===${NC}"
