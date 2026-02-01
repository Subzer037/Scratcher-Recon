#!/bin/bash

# Color variables for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Banner
echo -e "${YELLOW}
███████╗ ██████╗██████╗  █████╗ ████████╗ ██████╗██╗  ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔══██╗
███████╗██║     ██████╔╝███████║   ██║   ██║     ███████║█████╗  ██████╔╝
╚════██║██║     ██╔══██╗██╔══██║   ██║   ██║     ██║  ██║██╔══╝  ██║  ██╔  
███████║╚██████╗██║  ██║██║  ██║   ██║   ╚██████╗██║  ██║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                                 - By $ubzer0 aka Sujan Pisal
${NC}"
echo -e "${BLUE}A modular recon script for bug bounty hunters. (v7.1 - Strict Inputs)${NC}\n"

# ==========================================
# 1. INSTALLATION & REQUIREMENTS CHECK
# ==========================================

echo -e "${BLUE}[*] Checking system requirements and tools...${NC}"

# --- Function to install Go ---
install_go() {
    echo -e "${YELLOW}[*] Go not found. Starting Go installation...${NC}"
    
    # Wait for apt lock
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        sleep 3
    done

    # Install dependencies
    sudo apt update -y
    sudo apt install -y curl wget tar git

    # Get latest Go version
    GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n 1)

    if [[ ! $GO_VERSION =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[!] Failed to detect valid Go version.${NC}"
        exit 1
    fi

    GO_TAR="${GO_VERSION}.linux-amd64.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"

    echo -e "${YELLOW}[*] Installing Go version: $GO_VERSION${NC}"

    # Remove old Go
    sudo rm -rf /usr/local/go

    # Download & Extract
    wget -q --show-progress "$GO_URL"
    sudo tar -C /usr/local -xzf "$GO_TAR"
    rm -f "$GO_TAR"

    # Setup Environment Variables
    GO_ENV='
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
'
    # Update User .zshrc
    if [ -f "$HOME/.zshrc" ]; then
        if ! grep -q "GOROOT=/usr/local/go" "$HOME/.zshrc"; then
            echo "$GO_ENV" >> "$HOME/.zshrc"
        fi
    else
        # Fallback to .bashrc
        if ! grep -q "GOROOT=/usr/local/go" "$HOME/.bashrc"; then
            echo "$GO_ENV" >> "$HOME/.bashrc"
        fi
    fi

    echo -e "${GREEN}[✔] Go installation completed successfully!${NC}"
}

# --- Check Go Installation ---
if ! command -v go &> /dev/null && [ ! -d "/usr/local/go" ]; then
    install_go
else
    echo -e "${GREEN}[✔] Go is already installed.$(go version | awk '{print $3}')${NC}"
fi

# Export paths for current session
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# --- Function to Check and Install Tools ---
check_and_install() {
    local TOOL_NAME=$1
    local INSTALL_CMD=$2
    
    if command -v "$TOOL_NAME" &> /dev/null; then
        echo -e "${GREEN}[✔] Tool '$TOOL_NAME' already exists.${NC}"
    else
        echo -e "${YELLOW}[-] Tool '$TOOL_NAME' not found. Installing...${NC}"
        eval "$INSTALL_CMD"
    fi
}

# --- Install Tools ---
check_and_install "nmap" "sudo apt update && sudo apt install -y nmap"
check_and_install "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_and_install "subdominator" "go install -v github.com/d3mondev/subdominator@latest"
check_and_install "subzy" "go install -v github.com/LukaSikic/subzy@latest"

# UPDATED: httpx-toolkit installation logic
check_and_install "httpx-toolkit" "sudo apt update && sudo apt install -y httpx-toolkit || (go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && sudo mv \$(go env GOPATH)/bin/httpx /usr/local/bin/httpx-toolkit)"

check_and_install "katana" "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
check_and_install "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"
check_and_install "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"

# Install GF & Patterns
if ! command -v "gf" &> /dev/null; then
    echo -e "${YELLOW}[-] Tool 'gf' not found. Installing...${NC}"
    go install github.com/tomnomnom/gf@latest
    mkdir -p ~/.gf
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf_temp_patterns 2>/dev/null
    mv ~/.gf_temp_patterns/*.json ~/.gf/
    rm -rf ~/.gf_temp_patterns
    echo -e "${GREEN}[✔] GF and Patterns installed.${NC}"
fi

# Install Findomain
if ! command -v "findomain" &> /dev/null; then
    echo -e "${YELLOW}[-] Tool 'findomain' not found. Installing binary...${NC}"
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
    unzip -q findomain-linux.zip
    chmod +x findomain
    sudo mv findomain /usr/local/bin/findomain
    rm findomain-linux.zip
    echo -e "${GREEN}[✔] Findomain installed.${NC}"
fi

echo -e "${BLUE}======================================================${NC}\n"

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

# --- Clean Domain Input ---
clean_domain() {
    echo "$1" | sed -E 's|^\w+://||' | tr -d '/'
}

count_lines() {
    local file=$1
    if [ -f "$file" ]; then
        wc -l < "$file" | tr -d ' '
    else
        echo 0
    fi
}

# ==========================================
# 3. RECON LOGIC
# ==========================================

run_subdomain_enum() {
    echo -e "${BLUE}[*] Starting Subdomain Enumeration for: $DOMAIN${NC}"
    
    # Run tools
    subfinder -d "$DOMAIN" -o "$SUB_DIR/subfinder.txt" >/dev/null 2>&1
    findomain -t "$DOMAIN" -o >/dev/null 2>&1 && mv "${DOMAIN}.txt" "$SUB_DIR/findomain.txt" 2>/dev/null
    subdominator -d "$DOMAIN" -o "$SUB_DIR/subdominator.txt" >/dev/null 2>&1
    
    # Merge and Sort
    cat "$SUB_DIR"/*.txt 2>/dev/null | sort -u > "$SUB_DIR/final.subdomains.txt"
    
    # Subzy (Takeover)
    if [ -s "$SUB_DIR/final.subdomains.txt" ]; then
        subzy run --targets "$SUB_DIR/final.subdomains.txt" > "$SUB_DIR/subzy.final.txt"
    fi
    echo -e "${GREEN}[+] Subdomain enumeration complete.${NC}\n"
}

run_live_probe() {
    echo -e "${BLUE}[*] Probing for live web servers (200 OK only)...${NC}"
    if [ -s "$SUB_DIR/final.subdomains.txt" ]; then
        # UPDATED: Using httpx-toolkit with -mc 200
        httpx-toolkit -l "$SUB_DIR/final.subdomains.txt" -mc 200 -o "$SUB_DIR/live.subdomains.txt" -silent
        
        echo -e "${GREEN}[+] Live host probing complete. (Saved 200 OK only)${NC}\n"
    else
        echo -e "${RED}[!] No subdomains found to probe.${NC}\n"
    fi
}

run_url_discovery() {
    echo -e "${BLUE}[*] Starting URL Discovery on $DOMAIN...${NC}"
    
    echo -e "${YELLOW}[-] Running katana...${NC}"
    katana -u "$DOMAIN" -silent -o "$URL_DIR/katana.txt" >/dev/null 2>&1
    
    echo -e "${YELLOW}[-] Running waybackurls...${NC}"
    echo "$DOMAIN" | waybackurls -no-subs > "$URL_DIR/wayback.txt"
    
    echo -e "${YELLOW}[-] Running gau...${NC}"
    echo "$DOMAIN" | gau > "$URL_DIR/gau.txt"
    
    echo -e "${GREEN}[+] Merging URLs...${NC}"
    cat "$URL_DIR"/*.txt 2>/dev/null | sort -u > "$URL_DIR/final.urls.txt"
    echo -e "${GREEN}[+] URL discovery complete.${NC}\n"
}

run_gf_patterns() {
    echo -e "${BLUE}[*] Running GF patterns...${NC}"
    local FINAL_URLS="$URL_DIR/final.urls.txt"
    
    if [ -s "$FINAL_URLS" ]; then
        gf redirect "$FINAL_URLS" > "$GF_DIR/gfredirect.txt"
        gf xss "$FINAL_URLS" > "$GF_DIR/gfxss.txt"
        gf api-keys "$FINAL_URLS" > "$GF_DIR/gfapikeys.txt"
        echo -e "${GREEN}[+] GF pattern matching complete.${NC}\n"
    else
        echo -e "${RED}[!] No URLs found to scan.${NC}\n"
    fi
}

run_nmap_scan() {
    echo -e "${BLUE}[*] Starting Nmap Scan...${NC}"
    echo -e "${YELLOW}Select Nmap scan type:${NC}"
    echo "1. Top 1000 ports (Faster)"
    echo "2. All 65535 ports (Slower)"

    # STRICT INPUT VALIDATION LOOP
    while true; do
        read -p "Enter choice (1 or 2): " nmap_choice
        case $nmap_choice in
            1)
                echo -e "${YELLOW}[-] Running top 1000 port scan...${NC}"
                NMAP_ARGS="-sV"
                break
                ;;
            2)
                echo -e "${YELLOW}[-] Running full port scan...${NC}"
                NMAP_ARGS="-sV -p-"
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid input '$nmap_choice'. Please strictly enter 1 or 2.${NC}"
                ;;
        esac
    done

    nmap $NMAP_ARGS "$DOMAIN" -oN "$NMAP_FILE"
    echo -e "${GREEN}[+] Nmap scan complete.${NC}\n"
}

run_recon() {
    DOMAIN=$1
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}[*] Processing Target: $DOMAIN${NC}"
    echo -e "${BLUE}======================================================${NC}\n"

    # Directory Setup
    echo -e "${GREEN}[+] Creating directory structure for $DOMAIN...${NC}"
    mkdir -p "$DOMAIN"

    SUB_DIR="$DOMAIN/Subdomains"
    URL_DIR="$DOMAIN/URLs"
    GF_DIR="$DOMAIN/GFs"
    NMAP_FILE="$DOMAIN/nmap.txt"

    if [ "$RUN_SUBDOMAINS" = true ]; then
        mkdir -p "$SUB_DIR"
        run_subdomain_enum
        run_live_probe
    fi

    if [ "$RUN_URLS" = true ]; then
        mkdir -p "$URL_DIR"
        run_url_discovery
    fi

    if [ "$RUN_GF" = true ]; then
        mkdir -p "$GF_DIR"
        run_gf_patterns
    fi

    if [ "$RUN_NMAP" = true ]; then
        run_nmap_scan
    fi
}

# ==========================================
# 4. USER INPUT & EXECUTION
# ==========================================

declare -a DOMAINS

echo -e "${YELLOW}Choose an option:${NC}"
echo "1. Scan a single domain"
echo "2. Scan multiple domains"
read -p "Enter your choice (1 or 2): " choice

case $choice in
    1)
        read -p "Enter the domain name (e.g., example.com): " input_domain
        # Sanitize input immediately
        CLEANED_DOMAIN=$(clean_domain "$input_domain")
        
        if [ -n "$CLEANED_DOMAIN" ]; then
            DOMAINS+=("$CLEANED_DOMAIN")
            echo -e "${GREEN}[+] Target Set: $CLEANED_DOMAIN${NC}"
        else
            echo "${RED}[!] Invalid domain entered.${NC}"
            exit 1
        fi
        ;;
    2)
        read -p "How many domains? " num_domains
        if ! [[ "$num_domains" =~ ^[0-9]+$ ]]; then
            echo "Invalid number."
            exit 1
        fi
        for (( i=1; i<=num_domains; i++ )); do
            read -p "Enter domain #$i: " d_name
            CLEANED=$(clean_domain "$d_name")
            if [ -n "$CLEANED" ]; then
                DOMAINS+=("$CLEANED")
            fi
        done
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

# Scan Selection
RUN_SUBDOMAINS=false
RUN_URLS=false
RUN_GF=false
RUN_NMAP=false

echo -e "\n${YELLOW}Select Scans:${NC}"
echo "1. Subdomains & Live Probe"
echo "2. URL Discovery"
echo "3. GF Patterns"
echo "4. Nmap"
echo "5. ALL"
read -p "Enter choices (e.g. for single scan enter 1 or 3 and for multiple scan 1 2 3): " scan_choices

for sc in $scan_choices; do
    case $sc in
        1) RUN_SUBDOMAINS=true ;;
        2) RUN_URLS=true ;;
        3) RUN_GF=true ;;
        4) RUN_NMAP=true ;;
        5) RUN_SUBDOMAINS=true; RUN_URLS=true; RUN_GF=true; RUN_NMAP=true ;;
    esac
done

if [ "$RUN_GF" = true ] && [ "$RUN_URLS" = false ]; then
    echo -e "${YELLOW}[!] GF requires URLs. Enabling URL Discovery automatically.${NC}"
    RUN_URLS=true
fi

# Execute
for domain in "${DOMAINS[@]}"; do
    run_recon "$domain"
done

echo -e "${GREEN}\n[+] All scans finished! Happy Hunting! 🕵️‍♂️${NC}"
