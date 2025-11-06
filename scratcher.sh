#!/bin/bash

# Color variables for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
echo -e "${BLUE}A modular recon script for bug bounty hunters. (v7)${NC}\n"

# --- Function to count lines in a file ---
count_lines() {
    local file=$1
    if [ -f "$file" ]; then
        wc -l < "$file" | tr -d ' '
    else
        echo 0
    fi
}

# --- Recon Functions ---

run_subdomain_enum() {
    echo -e "${BLUE}[*] Starting Subdomain Enumeration...${NC}"
    subfinder -d $DOMAIN -o "$SUB_DIR/subfinder.txt" >/dev/null 2>&1
    findomain -t $DOMAIN -o >/dev/null 2>&1 && mv "$DOMAIN.txt" "$SUB_DIR/findomain.txt"
    subdominator -d $DOMAIN -o "$SUB_DIR/subdominator.txt" >/dev/null 2>&1
    cat "$SUB_DIR"/*.txt | sort -u > "$SUB_DIR/final.subdomains.txt"
    subzy run --targets "$SUB_DIR/final.subdomains.txt" > "$SUB_DIR/subzy.final.txt"
    echo -e "${GREEN}[+] Subdomain enumeration complete.${NC}\n"
}

run_live_probe() {
    echo -e "${BLUE}[*] Probing for live web servers (httprobe step)...${NC}"
    httpx -l "$SUB_DIR/final.subdomains.txt" -sc -o "$SUB_DIR/httprobe_status_codes.txt" -silent
    httpx -l "$SUB_DIR/final.subdomains.txt" -o "$SUB_DIR/live.subdomains.txt" -silent
    echo -e "${GREEN}[+] Live host probing complete.${NC}\n"
}

run_url_discovery() {
    # --- MODIFIED: Runs on main $DOMAIN only ---
    echo -e "${BLUE}[*] Starting URL Discovery on main domain ($DOMAIN)...${NC}"
    
    echo -e "${YELLOW}[-] Running katana on $DOMAIN...${NC}"
    katana -u $DOMAIN -silent -o "$URL_DIR/katana.txt" >/dev/null 2>&1
    
    echo -e "${YELLOW}[-] Running waybackurls on $DOMAIN...${NC}"
    echo "$DOMAIN" | waybackurls -no-subs > "$URL_DIR/wayback.txt"
    
    echo -e "${YELLOW}[-] Running gau on $DOMAIN...${NC}"
    echo "$DOMAIN" | gau > "$URL_DIR/gau.txt"
    
    echo -e "${GREEN}[+] Merging and sorting unique URLs...${NC}"
    cat "$URL_DIR"/*.txt | sort -u > "$URL_DIR/final.urls.txt"
    echo -e "${GREEN}[+] URL discovery complete.${NC}\n"
}

run_gf_patterns() {
    echo -e "${BLUE}[*] Running GF patterns on discovered URLs...${NC}"
    local FINAL_URLS="$URL_DIR/final.urls.txt"
    
    echo -e "${YELLOW}[-] Finding potential redirects...${NC}"
    gf redirect "$FINAL_URLS" > "$GF_DIR/gfredirect.txt"
    
    echo -e "${YELLOW}[-] Finding potential XSS...${NC}"
    gf xss "$FINAL_URLS" > "$GF_DIR/gfxss.txt"
    
    echo -e "${YELLOW}[-] Finding potential API keys...${NC}"
    gf api-keys "$FINAL_URLS" > "$GF_DIR/gfapikeys.txt"
    
    echo -e "${GREEN}[+] GF pattern matching complete.${NC}\n"
}

run_nmap_scan() {
    echo -e "${BLUE}[*] Starting Nmap Scan...${NC}"
    echo -e "${YELLOW}Select Nmap scan type:${NC}"
    echo "1. Top 1000 ports (Recommended, Faster)"
    echo "2. All 65535 ports (Very Slow)"
    read -p "Enter choice (1 or 2): " nmap_choice

    local NMAP_ARGS="-sV" # -sV for version detection
    if [ "$nmap_choice" == "2" ]; then
        NMAP_ARGS="$NMAP_ARGS -p-" # Scan all ports
        echo -e "${YELLOW}[-] Running Nmap all-port scan. This will take a long time...${NC}"
    else
        echo -e "${YELLOW}[-] Running Nmap top 1000 port scan...${NC}"
    fi

    nmap $NMAP_ARGS $DOMAIN -oN "$NMAP_FILE"
    echo -e "${GREEN}[+] Nmap scan complete.${NC}\n"
}

# --- Main Recon Function ---
run_recon() {
    DOMAIN=$1
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}[*] Starting Reconnaissance for: $DOMAIN${NC}"
    echo -e "${BLUE}======================================================${NC}\n"

    # --- Directory Setup (Dynamic) ---
    echo -e "${GREEN}[+] Creating base directory for $DOMAIN...${NC}"
    mkdir -p "$DOMAIN" # Create only the main folder

    # Define paths
    SUB_DIR="$DOMAIN/Subdomains"
    URL_DIR="$DOMAIN/URLs"
    GF_DIR="$DOMAIN/GFs"
    NMAP_FILE="$DOMAIN/nmap.txt"

    # --- Run selected scans & create folders JIT (Just-In-Time) ---
    
    if [ "$RUN_SUBDOMAINS" = true ]; then
        echo -e "${GREEN}[+] Creating Subdomains directory...${NC}"
        mkdir -p "$SUB_DIR"
        run_subdomain_enum
        run_live_probe # httprobe step is part of subdomain recon
    fi

    if [ "$RUN_URLS" = true ]; then
        echo -e "${GREEN}[+] Creating URLs directory...${NC}"
        mkdir -p "$URL_DIR"
        run_url_discovery
    fi

    if [ "$RUN_GF" = true ]; then
        echo -e "${GREEN}[+] Creating GFs directory...${NC}"
        mkdir -p "$GF_DIR"
        run_gf_patterns
    fi

    if [ "$RUN_NMAP" = true ]; then
        run_nmap_scan
    fi

    # --- Recon Summary for the Domain ---
    echo -e "${YELLOW}[+] Reconnaissance Summary for $DOMAIN:${NC}"
    echo "------------------------------------------"
    printf "%-25s %-10s\n" "Tool/File" "Count"
    echo "------------------------------------------"
    if [ -d "$SUB_DIR" ]; then
        printf "%-25s %-10s\n" "Subfinder" "$(count_lines "$SUB_DIR/subfinder.txt")"
        printf "%-25s %-10s\n" "Findomain" "$(count_lines "$SUB_DIR/findomain.txt")"
        printf "%-25s %-10s\n" "Subdominator" "$(count_lines "$SUB_DIR/subdominator.txt")"
        printf "%-25s %-10s\n" "Final Subdomains" "$(count_lines "$SUB_DIR/final.subdomains.txt")"
        printf "%-25s %-10s\n" "Takeovers (subzy)" "$(count_lines "$SUB_DIR/subzy.final.txt")"
        printf "%-25s %-10s\n" "Live Hosts (httpx)" "$(count_lines "$SUB_DIR/live.subdomains.txt")"
        printf "%-25s %-10s\n" "Host Status Codes" "$(count_lines "$SUB_DIR/httprobe_status_codes.txt")"
    fi
    if [ -d "$URL_DIR" ]; then
        echo "------------------------------------------"
        printf "%-25s %-10s\n" "Katana URLs" "$(count_lines "$URL_DIR/katana.txt")"
        printf "%-25s %-10s\n" "Wayback URLs" "$(count_lines "$URL_DIR/wayback.txt")"
        printf "%-25s %-10s\n" "GAU URLs" "$(count_lines "$URL_DIR/gau.txt")"
        printf "%-25s %-10s\n" "Final URLs" "$(count_lines "$URL_DIR/final.urls.txt")"
    fi
    if [ -d "$GF_DIR" ]; then
        echo "------------------------------------------"
        printf "%-25s %-10s\n" "GF Redirect" "$(count_lines "$GF_DIR/gfredirect.txt")"
        printf "%-25s %-10s\n" "GF XSS" "$(count_lines "$GF_DIR/gfxss.txt")"
        printf "%-25s %-10s\n" "GF API-Keys" "$(count_lines "$GF_DIR/gfapikeys.txt")"
    fi
    if [ -f "$NMAP_FILE" ]; then
        echo "------------------------------------------"
        printf "%-25s %-10s\n" "Nmap Scan" "$(count_lines "$NMAP_FILE")"
    fi
    echo "------------------------------------------"
    echo -e "${GREEN}[+] Recon for $DOMAIN is complete!${NC}\n"
}

# --- Script Start ---
declare -a DOMAINS

echo -e "${YELLOW}Choose an option:${NC}"
echo "1. Scan a single domain"
echo "2. Scan multiple domains"
read -p "Enter your choice (1 or 2): " choice

case $choice in
    1)
        read -p "Enter the domain name: " single_domain
        if [ -n "$single_domain" ]; then
            DOMAINS+=("$single_domain")
        else
            echo "No domain entered. Exiting."
            exit 1
        fi
        ;;
    2)
        read -p "How many domains do you want to scan? " num_domains
        if ! [[ "$num_domains" =~ ^[0-9]+$ ]] || [ "$num_domains" -le 0 ]; then
            echo "Invalid number. Exiting."
            exit 1
        fi
        for (( i=1; i<=num_domains; i++ )); do
            read -p "Enter domain #$i: " domain_name
            if [ -n "$domain_name" ]; then
                DOMAINS+=("$domain_name")
            fi
        done
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# --- Scan Selection ---
RUN_SUBDOMAINS=false
RUN_URLS=false
RUN_GF=false
RUN_NMAP=false

echo -e "\n${YELLOW}Which scans would you like to perform?${NC}"
echo "1. Subdomain Enumeration (subfinder, findomain, subzy, httpx)"
echo "2. URL Discovery (katana, gau, waybackurls)"
echo "3. GF Pattern Matching (xss, redirect, api-keys)"
echo "4. Nmap Port Scan"
echo "5. Run ALL scans"
read -p "Enter your choices (e.g., '1 3 4' or '5'): " scan_choices

for sc in $scan_choices; do
    case $sc in
        1) RUN_SUBDOMAINS=true ;;
        2) RUN_URLS=true ;;
        3) RUN_GF=true ;;
        4) RUN_NMAP=true ;;
        5)
            RUN_SUBDOMAINS=true
            RUN_URLS=true
            RUN_GF=true
            RUN_NMAP=true
            ;;
    esac
done

# --- Dependency Logic (MODIFIED) ---
# GF Patterns requires URL Discovery to run first.
if [ "$RUN_GF" = true ] && [ "$RUN_URLS" = false ]; then
    echo -e "${YELLOW}[!] Dependency: 'GF Patterns' requires 'URL Discovery'. Running it automatically.${NC}"
    RUN_URLS=true
fi
# URL Discovery no longer depends on Subdomain Enumeration.

# --- Loop through domains and run recon ---
for domain in "${DOMAINS[@]}"; do
    run_recon "$domain"
done

echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}All tasks are complete! Happy Hunting! 🕵️‍♂️${NC}"
echo -e "${BLUE}======================================================${NC}"
