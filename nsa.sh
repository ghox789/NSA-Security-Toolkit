#!/bin/bash

# NSA (Network Security Assistant) Helper Script
# A powerful tool to manage defensive security and privacy on Linux.
# Created by Yousuf Alkhanjari

# --- Configuration ---
SCRIPT_DIR="/root/.nsa"
CRED_FILE="$SCRIPT_DIR/users.db"
USER_CONFIG_DIR="$SCRIPT_DIR/users"
BACKUP_DIR="$SCRIPT_DIR/backups"
CURRENT_USER=""
declare -A USER_CONFIG
GSB_API_KEY="" # Add your Google Safe Browsing API Key here

# --- Colors for better output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Initial Setup ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root. Please use sudo.${NC}"
   exit 1
fi
mkdir -p "$SCRIPT_DIR" "$USER_CONFIG_DIR" "$BACKUP_DIR"

# --- NEW: Dependency Checker ---
dependency_checker() {
    local missing_packages=()
    local packages=("ufw" "openvpn" "macchanger" "chkrootkit" "clamav" "gnupg" "nmap" "htop" "nload" "speedtest-cli" "tor")
    
    echo -e "${CYAN}Checking for required packages...${NC}"
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            missing_packages+=("$pkg")
        fi
    done

    if [ ${#missing_packages[@]} -ne 0 ]; then
        echo -e "${YELLOW}The following required packages are missing:${NC} ${missing_packages[*]}"
        read -p "Do you want to try and install them now? (y/n): " choice
        if [[ "$choice" == "y" ]]; then
            # The package name for speedtest-cli can vary
            if [[ " ${missing_packages[*]} " =~ " speedtest-cli " ]]; then
                 apt-get update && apt-get install -y speedtest-cli || apt-get install -y python3-speedtest-cli
            fi
            apt-get update && apt-get install -y "${missing_packages[@]}"
        else
            echo -e "${RED}Cannot continue without required packages. Exiting.${NC}"
            exit 1
        fi
    fi
    # Specific check for anonsurf/Tor routing
    if [ ! -f "/usr/bin/anonsurf" ]; then
        echo -e "${YELLOW}'anonsurf' is not found. The Tor routing feature requires it.${NC}"
        echo -e "You can install it from sources like Parrot Security's repository."
        echo -e "Continuing without this specific feature enabled."
    fi
}

# --- Load/Save User Config ---
load_user_config() {
    local config_file="$USER_CONFIG_DIR/$CURRENT_USER.conf"
    if [ -f "$config_file" ]; then
        source "$config_file"
        USER_CONFIG["VPN_FILE"]=${VPN_FILE:-""}
    fi
}
save_user_config() {
    local config_file="$USER_CONFIG_DIR/$CURRENT_USER.conf"
    echo "VPN_FILE='${USER_CONFIG["VPN_FILE"]}'" > "$config_file"
}

# --- User Management ---
setup_admin_user() {
    echo -e "${YELLOW}--- First Time Setup: Create Your Admin User ---${NC}"
    read -p "Enter admin username: " username
    while true; do
        read -s -p "Enter a password: " password; echo
        read -s -p "Confirm password: " password2; echo
        [ "$password" = "$password2" ] && break
        echo -e "${RED}Passwords do not match. Please try again.${NC}"
    done
    local hashed_password=$(echo -n "$password" | sha256sum | awk '{print $1}')
    echo "$username:$hashed_password:admin" > "$CRED_FILE"
    chmod 600 "$CRED_FILE"
    echo -e "${GREEN}Admin user created. Please re-run the script to log in.${NC}"
    exit 0
}

login() {
    local attempts=3
    while [ $attempts -gt 0 ]; do
        read -p "Username: " input_username
        read -s -p "Password: " input_password; echo

        local user_data=$(grep "^$input_username:" "$CRED_FILE")
        if [ -z "$user_data" ]; then
            attempts=$((attempts-1))
            echo -e "${RED}Invalid username or password. You have $attempts attempt(s) left.${NC}"
            continue
        fi

        local stored_hash=$(echo "$user_data" | cut -d: -f2)
        local input_hash=$(echo -n "$input_password" | sha256sum | awk '{print $1}')

        if [ "$input_hash" = "$stored_hash" ]; then
            echo -e "${GREEN}Login successful!${NC}"
            CURRENT_USER=$input_username
            load_user_config
            return 0
        else
            attempts=$((attempts-1))
            echo -e "${RED}Invalid username or password. You have $attempts attempt(s) left.${NC}"
        fi
    done
    echo -e "${RED}Too many failed login attempts. Exiting.${NC}"
    exit 1
}

manage_users() {
    echo -e "${YELLOW}User management feature is not yet implemented.${NC}"
}

# --- Main Login & Dependency Check Logic ---
dependency_checker
if [ ! -f "$CRED_FILE" ]; then
    setup_admin_user
else
    login
fi

# --- Core Functions ---
get_public_ip() {
    echo -e "${YELLOW}Fetching public IP address...${NC}"
    IP_INFO=$(curl -s ipinfo.io)
    if [ -n "$IP_INFO" ]; then
        IP=$(echo "$IP_INFO" | grep '"ip"' | awk -F'"' '{print $4}')
        CITY=$(echo "$IP_INFO" | grep '"city"' | awk -F'"' '{print $4}')
        REGION=$(echo "$IP_INFO" | grep '"region"' | awk -F'"' '{print $4}')
        COUNTRY=$(echo "$IP_INFO" | grep '"country"' | awk -F'"' '{print $4}')
        echo -e "${GREEN}Current Public IP: $IP${NC}"
        echo -e "Location: $CITY, $REGION, $COUNTRY"
    else
        echo -e "${RED}Could not fetch public IP address. Check your internet connection.${NC}"
    fi
}

manage_firewall() {
    if ! command -v ufw &> /dev/null; then
        echo -e "${RED}UFW is not installed. Please install it with 'sudo apt-get install ufw'${NC}"
        return
    fi
    while true; do
        echo -e "\n--- Firewall Management ---"
        ufw status verbose
        echo "--------------------------"
        echo "1. Enable secure defaults (Deny incoming, Allow outgoing)"
        echo "2. Disable firewall (NOT RECOMMENDED)"
        echo "3. Allow a port (e.g., 22 for SSH)"
        echo "4. Deny a port"
        echo "b. Back to main menu"
        read -p "Choose an option: " fw_choice
        case $fw_choice in
            1) ufw default deny incoming; ufw default allow outgoing; ufw allow ssh; ufw --force enable; echo -e "${GREEN}Firewall enabled.${NC}";;
            2) ufw disable; echo -e "${RED}Firewall disabled.${NC}";;
            3) read -p "Enter port to ALLOW: " port; ufw allow $port;;
            4) read -p "Enter port to DENY: " port; ufw deny $port;;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

manage_vpn() {
    if ! command -v openvpn &> /dev/null; then echo -e "${RED}OpenVPN is not installed.${NC}"; return; fi
    while true; do
        echo -e "\n--- VPN & Anonymity Management ---"
        if pgrep -x "openvpn" > /dev/null; then echo -e "VPN Status: ${GREEN}CONNECTED${NC}"; else echo -e "VPN Status: ${RED}DISCONNECTED${NC}"; fi
        echo "--------------------------------"
        echo "1. Start VPN"
        echo "2. Stop VPN"
        echo "3. Activate VPN Kill Switch"
        echo "4. Deactivate VPN Kill Switch"
        echo "b. Back to main menu"
        read -p "Choose an option: " vpn_choice
        case $vpn_choice in
            1)
                read -e -p "Path to .ovpn file [${USER_CONFIG["VPN_FILE"]}]: " ovpn_file
                ovpn_file=${ovpn_file:-${USER_CONFIG["VPN_FILE"]}}
                if [ -f "$ovpn_file" ]; then
                    USER_CONFIG["VPN_FILE"]=$ovpn_file
                    save_user_config
                    openvpn --config "$ovpn_file" --daemon
                    sleep 5; echo -e "${GREEN}VPN initiated.${NC}"; get_public_ip
                else
                    echo -e "${RED}File not found: $ovpn_file${NC}"
                fi
                ;;
            2) killall openvpn; echo -e "${YELLOW}VPN disconnected.${NC}"; sleep 2; get_public_ip;;
            3) ufw --force reset; ufw default deny outgoing; ufw default deny incoming; ufw allow out on tun0 from any to any; ufw allow out on wlan0 to any port 53,67,68,1194 proto udp; ufw allow out on eth0 to any port 53,67,68,1194 proto udp; ufw --force enable; echo -e "${GREEN}Kill Switch ACTIVE.${NC}";;
            4) ufw --force reset; ufw default deny incoming; ufw default allow outgoing; ufw allow ssh; ufw --force enable; echo -e "${GREEN}Kill Switch INACTIVE.${NC}";;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

privacy_tools() {
    if ! command -v macchanger &> /dev/null; then echo -e "${YELLOW}macchanger not installed.${NC}"; return; fi
    while true; do
        echo -e "\n--- Privacy Tools ---"; ip -br addr; echo "--------------------------"
        echo "1. Randomize MAC address"; echo "2. Reset MAC to original"; echo "b. Back"
        read -p "Choose an option: " pt_choice
        case $pt_choice in
            1|2)
                read -p "Enter interface (e.g., eth0): " iface
                if ip link show $iface > /dev/null 2>&1; then
                    ip link set dev $iface down
                    [[ $pt_choice == 1 ]] && macchanger -r $iface || macchanger -p $iface
                    ip link set dev $iface up
                else
                    echo -e "${RED}Interface $iface not found.${NC}"
                fi
                ;;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

update_hosts_file() {
    echo -e "\n--- Threat Intelligence - Hosts Blocklist ---"
    read -p "This will replace your /etc/hosts file. A backup will be made. Continue? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo "Cancelled."; return; fi
    cp /etc/hosts /etc/hosts.nsa.bak
    if curl -s -o /etc/hosts "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"; then
        echo -e "${GREEN}Hosts file updated!${NC}"
    else
        echo -e "${RED}Download failed. Restoring backup.${NC}"; cp /etc/hosts.nsa.bak /etc/hosts
    fi
}

scan_threats() {
    if [ -z "$GSB_API_KEY" ]; then echo -e "${RED}Google Safe Browsing API key not set.${NC}"; return; fi
    read -p "Enter the full URL to scan: " url_to_scan
    echo -e "${CYAN}Scanning URL...${NC}"
    response=$(curl -s -H "Content-Type: application/json" -X POST -d '{"client":{"clientId":"nsa-script","clientVersion":"1.0.0"},"threatInfo":{"threatTypes":["MALWARE", "SOCIAL_ENGINEERING"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"'"$url_to_scan"'"}]}}' "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_API_KEY}")
    if [ -z "$response" ] || [ "$response" == "{}" ]; then
        echo -e "${GREEN}RESULT: The URL appears to be SAFE.${NC}"
    else
        echo -e "${RED}DANGER: The URL is flagged as a potential threat!${NC}"
    fi
}

system_hardening() {
    echo -e "\n--- System Hardening & Updates ---"
    read -p "Check for and apply system updates now? (y/n): " update_choice
    if [[ "$update_choice" == "y" ]]; then
        apt update && apt upgrade -y && apt autoremove -y
        echo -e "\n${GREEN}System update process complete.${NC}"
    else
        echo "Cancelled."
    fi
}

# --- NEW & UPDATED Functions ---
system_monitoring() {
    while true; do
        echo -e "\n--- System & Network Monitoring ---"
        echo "1. List active network connections"
        echo "2. View live firewall log"
        echo "3. Scan for rootkits (chkrootkit)"
        echo "4. Show live system processes (htop)"
        echo "5. Show live network traffic"
        echo "b. Back to main menu"
        read -p "Choose an option: " sm_choice
        case $sm_choice in
            1) ss -tunap ;;
            2) tail -f /var/log/ufw.log ;;
            3) chkrootkit ;;
            4) htop ;;
            5) nload ;;
            b) return ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
    done
}

file_security_tools() {
    while true; do
        echo -e "\n--- File Security Tools ---"
        echo "1. Scan a single file for malware (ClamAV)"
        echo "2. Scan entire home directory for malware (DEEP SCAN)"
        echo "3. Encrypt a file (GPG)"
        echo "4. Decrypt a file (GPG)"
        echo "b. Back to main menu"
        read -p "Choose an option: " fs_choice
        case $fs_choice in
            1) read -e -p "Enter file path to scan: " file; clamscan -i "$file";;
            2) 
                read -p "Scan entire home directory? This can be slow. (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then clamscan -r -i ~/; fi;;
            3) 
                read -e -p "Enter file path to encrypt: " file; gpg -c "$file"
                read -p "Securely delete original? (y/n): " shred
                if [[ "$shred" == "y" ]]; then shred -u "$file"; fi
                ;;
            4) read -e -p "Enter file path to decrypt: " file; gpg "$file";;
            b) return ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
    done
}

anonymity_tools() {
    if ! command -v anonsurf &> /dev/null; then echo -e "${RED}Anonsurf is not installed.${NC}"; return; fi
    while true; do
        echo -e "\n--- Anonymity Suite (Tor Routing) ---"; anonsurf status; echo "---------------------------------------"
        echo "1. Start Tor Anonymity Mode"; echo "2. Stop Tor Anonymity Mode"; echo "b. Back"
        read -p "Choose an option: " anon_choice
        case $anon_choice in
            1) anonsurf start ;;
            2) anonsurf stop ;;
            b) return ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
    done
}

network_tools() {
    while true; do
        echo -e "\n--- Network Tools ---"
        echo "1. Scan network security (checks router for open ports)"
        echo "2. Run Internet Speed Test"
        echo "b. Back to main menu"
        read -p "Choose an option: " net_choice
        case $net_choice in
            1) 
                local gateway=$(ip route | grep default | awk '{print $3}')
                if [ -z "$gateway" ]; then echo -e "${RED}Could not determine network gateway.${NC}"; else
                    echo -e "${CYAN}Scanning gateway ($gateway) for common vulnerable ports...${NC}"
                    nmap -p 21,22,23,25,80,110,139,443,445,3389,8080 "$gateway"
                    echo -e "${YELLOW}Check report. Open ports like 23 (telnet) could be a risk.${NC}"
                fi
                ;;
            2) speedtest-cli ;;
            b) return ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
    done
}

password_generator() {
    echo -e "\n--- Strong Password Generator ---"
    read -p "Enter desired password length (e.g., 16): " length
    if ! [[ "$length" =~ ^[0-9]+$ ]] || [ "$length" -lt 8 ]; then echo -e "${RED}Invalid length.${NC}"; return; fi
    local password=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$length")
    echo -e "${GREEN}Generated Password:${NC} $password"
}

security_recommendations() {
    echo -e "\n--- Security Hardening Recommendations ---"
    echo "1. ${YELLOW}Keep System Updated:${NC} Run 'System Hardening & Updates' regularly."
    echo "2. ${YELLOW}Use the Firewall:${NC} Ensure UFW is enabled with secure defaults."
    echo "3. ${YELLOW}Use a VPN:${NC} Always use a VPN on untrusted networks."
    echo "4. ${YELLOW}Strong Passwords:${NC} Use the password generator for unique passwords."
    echo "5. ${YELLOW}Beware of Phishing:${NC} Use the 'Scan URL' tool for suspicious links."
    echo "6. ${YELLOW}Regular Scans:${NC} Run rootkit and full malware scans periodically."
    echo "7. ${YELLOW}Encrypt Data:${NC} Use the file encryption tool for sensitive documents."
}

backup_restore() {
    while true; do
        echo -e "\n--- Backup & Restore ---"
        echo "1. Create a backup of all NSA users and configs"
        echo "2. Restore from a local backup"
        echo "b. Back to main menu"
        read -p "Choose an option: " br_choice
        case $br_choice in
            1) 
                local backup_file="$BACKUP_DIR/nsa_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                tar -czf "$backup_file" -C "$SCRIPT_DIR" .
                echo -e "${GREEN}Backup created at: $backup_file${NC}"
                ;;
            2)
                echo "Available backups:"; ls -1 "$BACKUP_DIR"/*.tar.gz
                read -e -p "Enter full path of backup to restore: " restore_file
                if [ -f "$restore_file" ]; then
                    read -p "This will overwrite all current users/settings! Are you sure? (y/n): " confirm
                    if [[ "$confirm" == "y" ]]; then
                        tar -xzf "$restore_file" -C "$SCRIPT_DIR"
                        echo -e "${GREEN}Restore complete. Please restart the script.${NC}"; exit 0
                    fi
                else echo -e "${RED}File not found.${NC}"; fi
                ;;
            b) return ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
    done
}

# --- Main Menu (Reorganized) ---
while true; do
    echo -e "\n${YELLOW}--- NSA (Network Security Assistant) | Logged in as: $CURRENT_USER ---${NC}"
    echo "      Credit: Yousuf Alkhanjari"
    echo "---------------------------------------"
    echo "1. Quick Status (IP & Location)"
    echo "2. Firewall Management"
    echo "3. VPN Management"
    echo "4. Anonymity Suite (Tor)"
    echo "5. Privacy Tools (MAC Changer)"
    echo "6. System & Network Monitoring"
    echo "7. Network Security Tools"
    echo "8. File Security Tools (Scan, Encrypt)"
    echo "9. Threat Intelligence (URL Scan, Blocklist)"
    echo "10. System Hardening & Updates"
    echo "11. Security Recommendations"
    echo "12. Password Generator"
    echo "13. Backup & Restore"
    echo "q. Quit"
    echo "---------------------------------------"
    read -p "Select an option: " choice

    case $choice in
        1) get_public_ip ;;
        2) manage_firewall ;;
        3) manage_vpn ;;
        4) anonymity_tools ;;
        5) privacy_tools ;;
        6) system_monitoring ;;
        7) network_tools ;;
        8) file_security_tools ;;
        9) while true; do
             echo -e "\n--- Threat Intelligence ---"; echo "1. Scan URL"; echo "2. Update Hosts Blocklist"; echo "b. Back"; read -p "> " tic
             case $tic in 1) scan_threats;; 2) update_hosts_file;; b) break;; *) echo "Invalid";; esac; done ;;
        10) system_hardening ;;
        11) security_recommendations ;;
        12) password_generator ;;
        13) backup_restore ;;
        q) echo "Exiting NSA. Stay safe."; exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}";;
    esac

    read -p "Press Enter to continue..."
done

