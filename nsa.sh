#!/bin/bash

# NSA (Network Security Assistant) Helper Script
# A powerful tool to manage defensive security and privacy on Linux.
# Created by Yousuf Alkhanjari

# --- Configuration ---
# NOTE: This script will create and manage files in /etc/nsa, using sudo when needed.
SCRIPT_DIR="/etc/nsa"
CRED_FILE="$SCRIPT_DIR/users.db"
USER_CONFIG_DIR="$SCRIPT_DIR/users"
VPN_CONFIG_DIR="$SCRIPT_DIR/vpn_configs"
BACKUP_DIR="$SCRIPT_DIR/backups"
PACKAGE_FLAG_FILE="$SCRIPT_DIR/.packages_installed"
ALERT_FILE="$SCRIPT_DIR/security.alerts"
QUARANTINE_DIR="$SCRIPT_DIR/quarantine"
REPORT_DIR="$SCRIPT_DIR/reports"
BOT_LOG_FILE="$SCRIPT_DIR/bot_activity.log"
CURRENT_USER=""
declare -A USER_CONFIG
GSB_API_KEY="" # Add your Google Safe Browsing API Key here

# --- Colors for better output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Sudo check and initial setup ---
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Warning: Running as root. It's recommended to run as a standard user.${NC}"
fi
sudo mkdir -p "$SCRIPT_DIR" "$USER_CONFIG_DIR" "$BACKUP_DIR" "$VPN_CONFIG_DIR" "$QUARANTINE_DIR" "$REPORT_DIR"
sudo touch "$BOT_LOG_FILE" "$CRED_FILE" "$ALERT_FILE"
sudo chmod -R 777 "$SCRIPT_DIR" # Make directory accessible to script for reading/writing alerts, logs etc.

# --- First Run Setup Assistants ---
setup_firewall_assistant() {
    echo -e "\n${YELLOW}--- First Run Firewall Setup ---${NC}"
    read -p "It is highly recommended to set up the firewall now. Continue? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        echo "Applying secure defaults: Deny all incoming, Allow all outgoing..."
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        read -p "Do you need to access this computer remotely via SSH? (y/n): " ssh_choice
        if [[ "$ssh_choice" == "y" ]]; then
            sudo ufw allow ssh
            echo "SSH port (22) has been allowed."
        fi
        sudo ufw --force enable
        echo -e "${GREEN}Firewall is now active and configured.${NC}"
    fi
}

setup_antivirus_assistant() {
    echo -e "\n${YELLOW}--- First Run Antivirus Setup ---${NC}"
    read -p "It is highly recommended to update the antivirus database now. This may take a few minutes. Continue? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        echo "Stopping background antivirus service..."
        sudo systemctl stop clamav-freshclam
        echo "Updating ClamAV signature database..."
        sudo freshclam
        echo "Restarting background antivirus service..."
        sudo systemctl start clamav-freshclam
        echo -e "${GREEN}Antivirus database updated.${NC}"
    fi
}


# --- Dependency Checker (Runs only once) ---
dependency_checker() {
    if sudo test -f "$PACKAGE_FLAG_FILE"; then
        return 0
    fi

    local missing_packages=()
    local packages=("ufw" "openvpn" "macchanger" "chkrootkit" "clamav" "clamav-daemon" "gnupg" "nmap" "htop" "nload" "speedtest-cli" "tor" "curl" "sqlite3")
    
    echo -e "${CYAN}First time setup: Checking for required packages...${NC}"
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            missing_packages+=("$pkg")
        fi
    done

    if [ ${#missing_packages[@]} -ne 0 ]; then
        echo -e "${YELLOW}The following required packages are missing:${NC} ${missing_packages[*]}"
        read -p "Do you want to try and install them now? (y/n): " choice
        if [[ "$choice" == "y" ]]; then
            if [[ " ${missing_packages[*]} " =~ " speedtest-cli " ]]; then
                 sudo apt-get update && sudo apt-get install -y speedtest-cli || sudo apt-get install -y python3-speedtest-cli
                 missing_packages=( "${missing_packages[@]/speedtest-cli}" )
            fi
            sudo apt-get update && sudo apt-get install -y "${missing_packages[@]}"
        else
            echo -e "${RED}Cannot continue without required packages. Exiting.${NC}"
            exit 1
        fi
    fi
    
    setup_firewall_assistant
    setup_antivirus_assistant
    
    sudo touch "$PACKAGE_FLAG_FILE"
    echo -e "${GREEN}All required packages are installed and initial setup is complete.${NC}"
}

# --- Helper function to run commands in a new terminal ---
run_in_new_terminal() {
    local cmd_to_run="$1"
    local title="$2"
    local final_cmd="$cmd_to_run; echo; read -p 'This window will close when you press Enter...'"

    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$title" -- bash -c "$final_cmd" &
    elif command -v konsole &> /dev/null; then
        konsole --new-tab --title "$title" -e bash -c "$final_cmd" &
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal --title="$title" -e "bash -c '$final_cmd'" &
    elif command -v xterm &> /dev/null; then
        xterm -T "$title" -e bash -c "$final_cmd" &
    else
        echo -e "${YELLOW}Could not find a supported terminal. Running in current window.${NC}"
        eval "$cmd_to_run"
    fi
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
    echo "$username:$hashed_password:admin" | sudo tee "$CRED_FILE" > /dev/null
    echo -e "${GREEN}Admin user created. Please re-run the script to log in.${NC}"
    exit 0
}

login() {
    local attempts=3
    echo -e "\n${YELLOW}--- NSA Security Toolkit ---${NC}"
    echo -e "${CYAN}    Created by Yousuf Alkhanjari${NC}"
    while [ $attempts -gt 0 ]; do
        read -p "Username: " input_username
        read -s -p "Password: " input_password; echo
        local user_data=$(sudo grep "^$input_username:" "$CRED_FILE")
        if [ -z "$user_data" ]; then
            attempts=$((attempts-1)); echo -e "${RED}Invalid username or password. You have $attempts attempt(s) left.${NC}"; continue
        fi
        local stored_hash=$(echo "$user_data" | cut -d: -f2)
        local input_hash=$(echo -n "$input_password" | sha256sum | awk '{print $1}')
        if [ "$input_hash" = "$stored_hash" ]; then
            echo -e "${GREEN}Login successful!${NC}"
            CURRENT_USER=$input_username
            USER_ROLE=$(echo "$user_data" | cut -d: -f3)
            return 0
        else
            attempts=$((attempts-1)); echo -e "${RED}Invalid username or password. You have $attempts attempt(s) left.${NC}"
        fi
    done
    echo -e "${RED}Too many failed login attempts. Exiting.${NC}"; exit 1
}

# --- Bot Management ---
bot_settings() {
    while true; do
        echo -e "\n--- Bot Settings ---"
        echo "1. Enable/Disable Primary Alert Bot"
        echo "2. Show Live Bot Activity Log"
        echo "3. List All Active Bots"
        echo "4. Create New Scheduled Scan (Bot)"
        echo "5. Delete a Scheduled Scan (Bot)"
        echo "6. Edit Bot Source Code (Advanced)"
        echo "b. Back to Admin Tools"
        read -p "Choose an option: " bot_choice
        case $bot_choice in
            1) # Enable/Disable Primary Bot
                if sudo crontab -l -u root 2>/dev/null | grep -q -- "--run-bot"; then
                    read -p "Primary bot is ENABLED. Disable it? (y/n): " choice
                    if [[ "$choice" == "y" ]]; then (sudo crontab -l -u root | grep -v -- "--run-bot") | sudo crontab -u root -; echo -e "${YELLOW}Bot disabled.${NC}"; fi
                else
                    read -p "Primary bot is DISABLED. Enable hourly checks? (y/n): " choice
                    if [[ "$choice" == "y" ]]; then (sudo crontab -l -u root 2>/dev/null; echo "0 * * * * $(realpath "$0") --run-bot") | sudo crontab -u root -; echo -e "${GREEN}Bot enabled.${NC}"; fi
                fi
                ;;
            2) # Show Live Activity
                run_in_new_terminal "sudo tail -f '$BOT_LOG_FILE'" "Live Bot Activity";;
            3) # List Bots
                echo -e "\n--- Active Bots (Scheduled Tasks) ---"
                sudo crontab -l -u root 2>/dev/null | grep "$(basename "$0")" || echo "No active bots found."
                ;;
            4) # Create Bot
                echo "Select bot type to create:"
                echo "1. Network Gateway Scan"
                echo "2. Deep File Scan (/home)"
                echo "3. System Rootkit Scan"
                read -p "Type: " type_choice
                
                echo "Select schedule:"
                echo "1. Hourly"
                echo "2. Daily (at 2 AM)"
                echo "3. Weekly (on Sunday at 3 AM)"
                read -p "Schedule: " sched_choice

                local schedule=""
                case $sched_choice in 1) schedule="0 * * * *";; 2) schedule="0 2 * * *";; 3) schedule="0 3 * * 0";; *) echo "${RED}Invalid.${NC}"; continue;; esac
                
                local command_flag=""
                case $type_choice in 1) command_flag="--run-network-scan";; 2) command_flag="--run-deep-scan";; 3) command_flag="--run-rootkit-scan";; *) echo "${RED}Invalid.${NC}"; continue;; esac
                
                (sudo crontab -l -u root 2>/dev/null; echo "$schedule $(realpath "$0") $command_flag") | sudo crontab -u root -
                echo -e "${GREEN}New bot created successfully.${NC}"
                ;;
            5) # Delete Bot
                echo "Select a bot to delete:"
                local bots=()
                while IFS= read -r line; do bots+=("$line"); done < <(sudo crontab -l -u root 2>/dev/null | grep "$(basename "$0")")
                
                if [ ${#bots[@]} -eq 0 ]; then echo "No bots to delete."; continue; fi
                
                for i in "${!bots[@]}"; do echo "$((i+1)). ${bots[$i]}"; done
                read -p "Enter number to delete (or 'c' to cancel): " del_choice
                if [[ "$del_choice" == "c" ]]; then continue; fi
                
                if [[ "$del_choice" =~ ^[0-9]+$ ]] && [ "$del_choice" -le "${#bots[@]}" ]; then
                    local line_to_delete="${bots[$((del_choice-1))]}"
                    (sudo crontab -l -u root | grep -vF "$line_to_delete") | sudo crontab -u root -
                    echo -e "${YELLOW}Bot deleted.${NC}"
                else
                    echo -e "${RED}Invalid selection.${NC}"
                fi
                ;;
            6) # Edit Source
                echo -e "${YELLOW}Opening script source code in nano. Be careful with changes.${NC}"
                echo "The bot functions are marked between '# --- BOT FUNCTIONS START ---' and '# --- BOT FUNCTIONS END ---'"
                read -p "Press Enter to continue..."
                sudo nano "$(realpath "$0")"
                ;;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

# --- BOT FUNCTIONS START ---
# This section contains the individual bot functions
run_automation_bot() {
    # Main hourly alert bot
    sudo bash -c "echo \"\$(date): Starting hourly security scan...\" >> \"$BOT_LOG_FILE\""
    sudo bash -c "> \"$ALERT_FILE\""
    
    # 1. Check for failed logins
    sudo bash -c "echo \"\$(date): Scanning for failed login attempts...\" >> \"$BOT_LOG_FILE\""
    local failed_logins=$(sudo journalctl --since "1 hour ago" | grep -Ei "failed password|authentication failure")
    if [ -n "$failed_logins" ]; then
        local attacker_ip=$(echo "$failed_logins" | grep -oE 'from [^ ]+' | sed 's/from //' | sort | uniq -c | sort -nr | head -n 1 | awk '{print $2}')
        if [ -n "$attacker_ip" ]; then
            sudo bash -c "echo \"FAILED_LOGIN:High number of failed logins detected from IP: $attacker_ip\" >> \"$ALERT_FILE\""
            sudo bash -c "echo \"\$(date): ALERT! High-volume failed logins from $attacker_ip\" >> \"$BOT_LOG_FILE\""
        fi
    fi

    # 2. Scan Downloads folder for new files
    sudo bash -c "echo \"\$(date): Scanning recent downloads for malware...\" >> \"$BOT_LOG_FILE\""
    local user_homes=$(getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $6}')
    for home in $user_homes; do
        local downloads_dir="$home/Downloads"
        if [ -d "$downloads_dir" ]; then
            find "$downloads_dir" -type f -mmin -60 -print0 | while IFS= read -r -d $'\0' file; do
                local scan_result=$(sudo clamscan --infected --no-summary -r "$file")
                if [ -n "$scan_result" ]; then
                    local virus_name=$(echo "$scan_result" | awk -F': ' '{print $2}')
                    sudo bash -c "echo \"MALWARE_FOUND:File:'$file':Threat:'$virus_name'\" >> \"$ALERT_FILE\""
                    sudo bash -c "echo \"\$(date): ALERT! Malware '$virus_name' found in '$file'\" >> \"$BOT_LOG_FILE\""
                fi
            done
        fi
    done
    sudo bash -c "echo \"\$(date): Hourly scan complete.\" >> \"$BOT_LOG_FILE\""
}
run_network_scan_bot() {
    sudo bash -c "echo \"\$(date): Starting scheduled network scan...\" >> \"$BOT_LOG_FILE\""
    local gateway=$(ip route | grep default | awk '{print $3}')
    if [ -n "$gateway" ]; then
        sudo nmap -p 21,22,23,25,80,110,139,443,445,3389,8080 "$gateway" | sudo tee -a "$BOT_LOG_FILE" > /dev/null
    fi
    sudo bash -c "echo \"\$(date): Network scan complete.\" >> \"$BOT_LOG_FILE\""
}
run_deep_scan_bot() {
    sudo bash -c "echo \"\$(date): Starting scheduled deep file scan...\" >> \"$BOT_LOG_FILE\""
    sudo clamscan -r /home --infected | sudo tee -a "$BOT_LOG_FILE" > /dev/null
    sudo bash -c "echo \"\$(date): Deep file scan complete.\" >> \"$BOT_LOG_FILE\""
}
run_rootkit_scan_bot() {
    sudo bash -c "echo \"\$(date): Starting scheduled rootkit scan...\" >> \"$BOT_LOG_FILE\""
    sudo chkrootkit | sudo tee -a "$BOT_LOG_FILE" > /dev/null
    sudo bash -c "echo \"\$(date): Rootkit scan complete.\" >> \"$BOT_LOG_FILE\""
}
# --- BOT FUNCTIONS END ---

manage_users_submenu() {
    while true; do
        echo -e "\n--- User Management ---"
        echo "1. Add a new user"
        echo "2. Delete a user"
        echo "3. Change user role"
        echo "4. List all users"
        echo "b. Back to Admin Tools"
        read -p "Choose an option: " user_choice
        case $user_choice in
            1) # Add User
                read -p "Enter new username: " new_user
                if sudo grep -q "^$new_user:" "$CRED_FILE"; then echo -e "${RED}User already exists.${NC}"; continue; fi
                while true; do
                    read -s -p "Enter password for $new_user: " pass; echo
                    read -s -p "Confirm password: " pass2; echo
                    [ "$pass" = "$pass2" ] && break
                    echo -e "${RED}Passwords do not match.${NC}"
                done
                local new_hash=$(echo -n "$pass" | sha256sum | awk '{print $1}')
                echo "$new_user:$new_hash:user" | sudo tee -a "$CRED_FILE" > /dev/null
                sudo touch "$USER_CONFIG_DIR/$new_user.conf"
                echo -e "${GREEN}User '$new_user' created successfully.${NC}"
                ;;
            2) # Delete User
                echo "Users available to delete:"
                sudo grep ":user$" "$CRED_FILE" | cut -d: -f1
                read -p "Enter username to delete: " user_to_del
                if [ -z "$user_to_del" ]; then continue; fi
                if sudo grep -q "^$user_to_del:.*:admin$" "$CRED_FILE"; then echo -e "${RED}Cannot delete an admin user.${NC}"; continue; fi
                sudo sed -i "/^$user_to_del:/d" "$CRED_FILE"
                sudo rm -f "$USER_CONFIG_DIR/$user_to_del.conf"
                echo -e "${YELLOW}User '$user_to_del' has been deleted.${NC}"
                ;;
            3) # Change User Role
                echo "Users:"
                sudo cut -d: -f1,3 "$CRED_FILE"
                read -p "Enter username to modify: " user_to_change
                if ! sudo grep -q "^$user_to_change:" "$CRED_FILE"; then echo -e "${RED}User not found.${NC}"; continue; fi
                
                local current_role=$(sudo grep "^$user_to_change:" "$CRED_FILE" | cut -d: -f3)
                read -p "Change role to 'admin' or 'user'? (current: $current_role): " new_role
                if [[ "$new_role" != "admin" && "$new_role" != "user" ]]; then echo -e "${RED}Invalid role.${NC}"; continue; fi

                if [[ "$current_role" == "admin" && $(sudo grep -c ":admin$" "$CRED_FILE") -eq 1 ]]; then
                    echo -e "${RED}Cannot demote the last admin user.${NC}"; continue;
                fi

                local hash=$(sudo grep "^$user_to_change:" "$CRED_FILE" | cut -d: -f2)
                sudo sed -i "s/^$user_to_change:.*/$user_to_change:$hash:$new_role/" "$CRED_FILE"
                echo -e "${GREEN}User $user_to_change is now an $new_role.${NC}"
                ;;
            4) # List Users
                echo "--- User List ---"; sudo cut -d: -f1,3 "$CRED_FILE";;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}


manage_admin_tools() {
    # This function is now the main entry point for Admin tools
    if [ "$USER_ROLE" != "admin" ]; then
        echo -e "${RED}Access Denied. This feature is for admin users only.${NC}"; return
    fi
    while true; do
        echo -e "\n--- Admin Tools ---"
        echo "1. User Management (Add, Delete, Change Role)"
        echo "2. Bot Settings"
        echo "b. Back to main menu"
        read -p "Choose an option: " admin_choice
        case $admin_choice in
            1) manage_users_submenu;;
            2) bot_settings;;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}


# --- Main Login & Dependency Check Logic ---
case "$1" in
    --run-bot) run_automation_bot; exit 0;;
    --run-csv-reporter) run_csv_reporter; exit 0;;
    --run-network-scan) run_network_scan_bot; exit 0;;
    --run-deep-scan) run_deep_scan_bot; exit 0;;
    --run-rootkit-scan) run_rootkit_scan_bot; exit 0;;
esac

dependency_checker
if ! sudo test -f "$CRED_FILE" || ! sudo test -s "$CRED_FILE"; then
    setup_admin_user
else
    login
fi

# --- Core Functions ---
show_quick_status() {
    echo -e "\n${YELLOW}--- NSA Quick Status Dashboard ---${NC}"
    echo -e "${CYAN}Public IP & Location:${NC}"
    curl -s ipinfo.io | grep -E "ip|city|region|country" | sed 's/"//g; s/,//' | awk '{print "  " $1 " " $2}'
    echo ""
    echo -e "${CYAN}System Information:${NC}"
    echo "  Hostname: $(hostname)"
    echo "  Kernel: $(uname -r)"
    echo ""
    echo -e "${CYAN}Security Status:${NC}"
    echo -n "  Firewall: " && sudo ufw status | head -n 1
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -vc "Listing...")
    echo "  Pending Updates: ${UPDATES} packages"
    echo ""
    echo -e "${CYAN}Network Speed:${NC}"
    speedtest-cli --simple | grep -E "Download|Upload"
    echo ""
    echo -e "${CYAN}Disk Usage:${NC}"
    df -h | grep -E "^/dev/|Filesystem"
}

manage_firewall() {
    while true; do
        echo -e "\n--- Firewall Management ---"
        sudo ufw status numbered
        echo "--------------------------"
        echo "1. Enable secure defaults"
        echo "2. Disable firewall"
        echo "3. Allow a port"
        echo "4. Deny a port"
        echo "5. Delete a rule by number"
        echo "b. Back to main menu"
        read -p "Choose an option: " fw_choice
        case $fw_choice in
            1) sudo ufw default deny incoming; sudo ufw default allow outgoing; sudo ufw allow ssh; sudo ufw --force enable; echo -e "${GREEN}Firewall enabled.${NC}";;
            2) sudo ufw disable; echo -e "${RED}Firewall disabled.${NC}";;
            3) read -p "Enter port to ALLOW: " port; sudo ufw allow $port;;
            4) read -p "Enter port to DENY: " port; sudo ufw deny $port;;
            5) read -p "Enter rule number to DELETE: " num; sudo ufw --force delete $num;;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

manage_vpn() {
    while true; do
        echo -e "\n--- VPN & Anonymity Management ---"
        if pgrep -x "openvpn" > /dev/null; then echo -e "VPN Status: ${GREEN}CONNECTED${NC}"; else echo -e "VPN Status: ${RED}DISCONNECTED${NC}"; fi
        echo "Current Config: ${USER_CONFIG["VPN_FILE"]:-Not Set}"
        echo "--------------------------------"
        echo "1. Start VPN"
        echo "2. Stop VPN"
        echo "3. Activate VPN Kill Switch"
        echo "4. Deactivate VPN Kill Switch"
        echo "b. Back to main menu"
        read -p "Choose an option: " vpn_choice
        case $vpn_choice in
            1)
                read -p "Use local file or download from URL? (f/u): " source_choice
                local ovpn_file=""
                if [[ "$source_choice" == "u" ]]; then
                    read -p "Enter URL for .ovpn file: " vpn_url
                    local filename=$(basename "$vpn_url")
                    ovpn_file="$VPN_CONFIG_DIR/$filename"
                    echo "Downloading to $ovpn_file..."
                    sudo curl -L -o "$ovpn_file" "$vpn_url"
                else
                    read -e -p "Path to local .ovpn file [${USER_CONFIG["VPN_FILE"]}]: " ovpn_file
                    ovpn_file=${ovpn_file:-${USER_CONFIG["VPN_FILE"]}}
                fi
                if [ -f "$ovpn_file" ]; then
                    USER_CONFIG["VPN_FILE"]=$ovpn_file # This doesn't need sudo, it's a script variable
                    sudo openvpn --config "$ovpn_file" --daemon
                    sleep 5; echo -e "${GREEN}VPN initiated.${NC}"; show_quick_status
                else
                    echo -e "${RED}VPN file not found: $ovpn_file${NC}"
                fi
                ;;
            2) sudo killall openvpn; echo -e "${YELLOW}VPN disconnected.${NC}"; sleep 2; show_quick_status;;
            3) sudo ufw --force reset; sudo ufw default deny outgoing; sudo ufw default deny incoming; sudo ufw allow out on tun0 from any to any; sudo ufw allow out to any port 53,67,68,1194 proto udp; sudo ufw --force enable; echo -e "${GREEN}Kill Switch ACTIVE.${NC}";;
            4) sudo ufw --force reset; sudo ufw default deny incoming; sudo ufw default allow outgoing; sudo ufw allow ssh; sudo ufw --force enable; echo -e "${GREEN}Kill Switch INACTIVE.${NC}";;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

log_monitoring() {
    while true; do
        echo -e "\n--- Live Log Monitoring ---"
        echo "1. Firewall Log (ufw)"
        echo "2. Authentication Log (logins, sudo)"
        echo "3. System Log (kernel, services)"
        echo "4. Automation Bot Activity Log"
        echo "b. Back to main menu"
        read -p "Choose a log to view: " log_choice
        case $log_choice in
            1) 
                local ufw_log="/var/log/ufw.log"
                if [ -f "$ufw_log" ]; then run_in_new_terminal "sudo tail -f '$ufw_log'" "Live Firewall Log"; else echo -e "${YELLOW}Firewall log not found or requires root to check.${NC}"; fi;;
            2) 
                run_in_new_terminal "sudo journalctl -f SYSLOG_FACILITY=4 SYSLOG_FACILITY=10" "Live Authentication Log";;
            3) 
                run_in_new_terminal "sudo journalctl -f" "Live System Log";;
            4) run_in_new_terminal "sudo tail -f '$BOT_LOG_FILE'" "Live Bot Activity";;
            b) return;;
            *) echo -e "${RED}Invalid option.${NC}";;
        esac
    done
}

generate_reports() {
    while true; do
        echo -e "\n--- Security Reporting ---"
        echo "1. Firewall Block Report"
        echo "2. Successful Login Report (Last 24h)"
        echo "3. Failed Login Report (Last 24h)"
        echo "b. Back to main menu"
        read -p "Choose a report to generate: " report_choice
        case $report_choice in
            1) # Firewall Report
                echo -e "\n${YELLOW}--- Firewall Block Report ---${NC}"
                local ufw_log="/var/log/ufw.log"
                if ! sudo test -f "$ufw_log"; then echo -e "${RED}Firewall log not found.${NC}"; continue; fi
                
                local total_blocks=$(sudo grep -c "\[UFW BLOCK\]" "$ufw_log")
                echo -e "Total connections blocked: ${YELLOW}$total_blocks${NC}"
                
                if [ "$total_blocks" -gt 0 ]; then
                    echo -e "\n${CYAN}Top 10 Attacking IPs:${NC}"
                    sudo grep "\[UFW BLOCK\]" "$ufw_log" | grep -oE 'SRC=[^ ]+' | sed 's/SRC=//' | sort | uniq -c | sort -nr | head -n 10
                    
                    echo -e "\n${CYAN}Top 10 Targeted Ports:${NC}"
                    sudo grep "\[UFW BLOCK\]" "$ufw_log" | grep -oE 'DPT=[^ ]+' | sed 's/DPT=//' | sort | uniq -c | sort -nr | head -n 10
                fi
                ;;
            2) # Successful Logins
                echo -e "\n${YELLOW}--- Successful Logins (Last 24 Hours) ---${NC}"
                sudo journalctl --since "24 hours ago" | grep "session opened for user" | sed -E 's/^.*session opened for user ([^ ]+).*$/  - \1/' | sort | uniq -c
                ;;
            3) # Failed Logins
                echo -e "\n${YELLOW}--- Failed Login Attempts (Last 24 Hours) ---${NC}"
                local failed_logins=$(sudo journalctl --since "24 hours ago" | grep -Ei "failed password|authentication failure|invalid user")
                if [ -z "$failed_logins" ]; then
                    echo -e "${GREEN}No failed login attempts recorded in the last 24 hours.${NC}"
                else
                    echo -e "${RED}Potential brute-force activity detected!${NC}"
                    echo -e "\n${CYAN}Top 10 Attacker IPs:${NC}"
                    echo "$failed_logins" | grep -oE 'from [^ ]+' | sed 's/from //' | sort | uniq -c | sort -nr | head -n 10
                    echo -e "\n${CYAN}Full failure log:${NC}"
                    echo "$failed_logins"
                fi
                ;;
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
                    sudo ip link set dev $iface down
                    [[ $pt_choice == 1 ]] && sudo macchanger -r $iface || sudo macchanger -p $iface
                    sudo ip link set dev $iface up
                    echo -e "${GREEN}Action completed for $iface.${NC}"
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
    sudo cp /etc/hosts /etc/hosts.nsa.bak
    if curl -s -o /tmp/hosts "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"; then
        sudo mv /tmp/hosts /etc/hosts
        echo -e "${GREEN}Hosts file updated!${NC}"
    else
        echo -e "${RED}Download failed. Restoring backup.${NC}"; sudo cp /etc/hosts.nsa.bak /etc/hosts
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
        sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
        echo -e "\n${GREEN}System update process complete.${NC}"
    else
        echo "Cancelled."
    fi
}

system_monitoring() {
    while true; do
        echo -e "\n--- System & Network Monitoring ---"
        echo "1. List active network connections"
        echo "2. Scan for rootkits (chkrootkit)"
        echo "3. Show live system processes (htop)"
        echo "4. Show live network traffic (nload)"
        echo "b. Back to main menu"
        read -p "Choose an option: " sm_choice
        case $sm_choice in
            1) sudo ss -tunap ;;
            2) sudo chkrootkit ;;
            3) run_in_new_terminal "htop" "System Processes" ;;
            4) run_in_new_terminal "nload" "Network Traffic" ;;
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
            1) read -e -p "Enter file path to scan: " file; sudo clamscan -i "$file";;
            2) 
                read -p "Scan entire home directory? This can be slow. (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then sudo clamscan -r -i /home; fi;;
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
        echo -e "\n--- Anonymity Suite (Tor Routing) ---"; sudo anonsurf status; echo "---------------------------------------"
        echo "1. Start Tor Anonymity Mode"; echo "2. Stop Tor Anonymity Mode"; echo "b. Back"
        read -p "Choose an option: " anon_choice
        case $anon_choice in
            1) sudo anonsurf start ;;
            2) sudo anonsurf stop ;;
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
                    sudo nmap -p 21,22,23,25,80,110,139,443,445,3389,8080 "$gateway"
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
                local backup_file="$HOME/nsa_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                sudo tar -czf "$backup_file" -C "$SCRIPT_DIR" .
                sudo chown $USER:$USER "$backup_file"
                echo -e "${GREEN}Backup created at: $backup_file${NC}"
                ;;
            2)
                read -e -p "Enter full path of backup to restore: " restore_file
                if [ -f "$restore_file" ]; then
                    read -p "This will overwrite all current users/settings! Are you sure? (y/n): " confirm
                    if [[ "$confirm" == "y" ]]; then
                        sudo tar -xzf "$restore_file" -C "$SCRIPT_DIR"
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
    echo -e "\n${YELLOW}--- NSA (Network Security Assistant) | Logged in as: $CURRENT_USER ($USER_ROLE) ---${NC}"
    echo "      Credit: Yousuf Alkhanjari"
    
    bot_status="${RED}DISABLED${NC}"
    if sudo crontab -l -u root 2>/dev/null | grep -q -- "--run-bot"; then
        bot_status="${GREEN}ENABLED${NC}"
    fi
    csv_status="${RED}DISABLED${NC}"
    if sudo crontab -l -u root 2>/dev/null | grep -q -- "--run-csv-reporter"; then
        csv_status="${GREEN}ENABLED${NC}"
    fi
    echo "      Automation Bot: $bot_status | CSV Reporting: $csv_status"
    
    if sudo test -s "$ALERT_FILE"; then
        echo "----------------------------------------------------"
        echo -e "${RED}         >>> SECURITY ALERT DETECTED <<<${NC}"
    fi

    echo "----------------------------------------------------"
    if sudo test -s "$ALERT_FILE"; then echo -e "${YELLOW}v. View Security Alerts${NC}"; fi
    echo "1. Quick Status Dashboard"
    echo "2. Firewall Management"
    echo "3. VPN Management"
    echo "4. Anonymity Suite (Tor)"
    echo "5. Live Log Monitoring"
    echo "6. System & Network Monitoring (htop, nload)"
    echo "7. Network Security Tools (nmap, speedtest)"
    echo "8. File Security Tools (Scan, Encrypt)"
    echo "9. Threat Intelligence"
    echo "10. System Hardening & Updates"
    echo "11. Security Recommendations"
    echo "12. Password Generator"
    echo "13. Backup & Restore"
    echo "14. Generate Security Reports"
    if [ "$USER_ROLE" == "admin" ]; then echo "a. Admin Tools"; fi
    echo "q. Quit"
    echo "----------------------------------------------------"
    read -p "Select an option: " choice

    case $choice in
        v) if sudo test -s "$ALERT_FILE"; then view_security_alerts; else echo -e "${RED}Invalid option.${NC}"; fi ;;
        1) show_quick_status ;;
        2) manage_firewall ;;
        3) manage_vpn ;;
        4) anonymity_tools ;;
        5) log_monitoring ;;
        6) system_monitoring ;;
        7) network_tools ;;
        8) file_security_tools ;;
        9) while true; do
             echo -e "\n--- Threat Intelligence ---"
             echo "1. Scan URL for Threats"
             echo "2. Update Hosts Blocklist"
             echo "3. Scan Browser History for Threats"
             echo "b. Back to Main Menu"
             read -p "> " tic
             case $tic in 
                1) scan_threats;; 
                2) update_hosts_file;; 
                3) scan_browser_history;;
                b) break;; 
                *) echo "Invalid";; 
             esac; done ;;
        10) system_hardening ;;
        11) security_recommendations ;;
        12) password_generator ;;
        13) backup_restore ;;
        14) generate_reports ;;
        a) if [ "$USER_ROLE" == "admin" ]; then manage_admin_tools; else echo -e "${RED}Invalid option.${NC}"; fi ;;
        q) echo "Exiting NSA. Stay safe."; exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}";;
    esac

    read -p "Press Enter to continue..."
done

