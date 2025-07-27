#!/bin/bash

# ===========================================
# Script: Automatic File Permissions Audit
# Description: Scans critical directories for files/folders with too broad permissions (e.g., 777).
# ===========================================

# Basic settings
set -Eeuo pipefail
LC_ALL=C

# Colors
declare -A colors=(
    ["RED"]='\e[31m'
    ["GREEN"]='\e[32m'
    ["YELLOW"]='\e[33m'
    ["BLUE"]='\e[34m'
    ["PURPLE"]='\e[35m'
    ["CYAN"]='\e[36m'
    ["WHITE"]='\e[37m'
    ["RESET"]='\e[0m'
)

# Global variables
DESKTOP_PATH="$HOME/Desktop"
REPORT_FILE="security_audit_report_file_permissions_$(date +%Y-%m-%d-%I-%M-%p).txt"
FMT='%m %M %u %g %s %TY-%Tm-%Td %TH:%TM %p\n'
HOST="$(hostname -f 2>/dev/null || hostname || echo unknown)"
USER_RUN="$(id -un 2>/dev/null || echo unknown)"

# Default directories to scan - critical system locations
DEFAULT_DIRS=(
    # System configuration
    /etc
    /etc/security
    /etc/ssl
    /etc/ssh
    /etc/pam.d
    /etc/sudoers.d
    /etc/cron.d
    /etc/cron.daily
    /etc/cron.hourly
    /etc/cron.weekly
    /etc/cron.monthly
    /etc/systemd
    /etc/init.d
    /etc/logrotate.d
    /etc/apache2
    /etc/nginx
    /etc/mysql
    /etc/postgresql
    /etc/php
    
    # Variable data
    /var
    /var/www
    /var/log
    /var/mail
    /var/spool
    /var/lib
    /var/backups
    
    # User directories
    /home
    /root
    
    # System binaries and libraries
    /usr/local
    /usr/local/bin
    /usr/local/sbin
    /usr/bin
    /usr/sbin
    /bin
    /sbin
    /lib
    /lib64
    
    # Optional packages
    /opt
    
    # Server data
    /srv
    
    # Web directories
    /var/www/html
    /var/www/cgi-bin
    
    # Database directories
    /var/lib/mysql
    /var/lib/postgresql
    
    # Mail directories
    /var/mail
    /var/spool/mail
    
    # Temporary directories
    /tmp
    /var/tmp
    
    # Application directories
    /usr/share
    /usr/local/share
    
    # Boot files
    /boot
)

# Common find exclusions - comprehensive security-focused list
FIND_COMMON=(
    -ignore_readdir_race 
    -xdev
    
    # System virtual filesystems
    -not -path "/proc/*"
    -not -path "/sys/*"
    -not -path "/run/*"
    -not -path "/dev/*"
    -not -path "/snap/*"
    
    # Package management
    -not -path "/var/cache/apt/*"
    -not -path "/var/lib/apt/*"
    -not -path "/var/lib/dpkg/*"
    -not -path "/var/cache/yum/*"
    -not -path "/var/lib/yum/*"
    
    # Temporary files
    -not -path "/var/tmp/*"
    -not -path "/tmp/*"
    -not -path "*/tmp/*"
    -not -path "*/.cache/*"
    
    # Version control
    -not -path "*/.git/*"
    -not -path "*/.svn/*"
    -not -path "*/.bzr/*"
    -not -path "*/.hg/*"
    
    # Build directories
    -not -path "*/node_modules/*"
    -not -path "*/build/*"
    -not -path "*/dist/*"
    -not -path "*/__pycache__/*"
    
    # Log files
    -not -path "/var/log/journal/*"
    -not -path "/var/log/apache2/*"
    -not -path "/var/log/nginx/*"
    -not -path "/var/log/mysql/*"
    -not -path "/var/log/postgresql/*"
    -not -path "*/logs/*"
    
    # User specific
    -not -path "/home/*/.local/share/*"
    -not -path "/home/*/.config/*"
    -not -path "/home/*/.cache/*"
    -not -path "/home/*/.mozilla/*"
    -not -path "/home/*/.chrome/*"
    -not -path "/home/*/.npm/*"
    -not -path "/home/*/.yarn/*"
    -not -path "/home/*/.pip/*"
    
    # Container and VM related
    -not -path "/var/lib/docker/*"
    -not -path "/var/lib/containerd/*"
    -not -path "/var/lib/lxc/*"
    -not -path "/var/lib/libvirt/*"
    -not -path "/var/lib/vmware/*"
    -not -path "/var/lib/virtualbox/*"
    
    # Backup files
    -not -path "*/backup/*"
    -not -path "*~"
    -not -path "*.bak"
    -not -path "*.old"
    -not -path "*.orig"
    
    # Media and uploads
    -not -path "/var/www/html/media/*"
    -not -path "/var/www/html/uploads/*"
    -not -path "*/public/uploads/*"
    -not -path "*/media/*"
    -not -path "*/uploads/*"
    
    # Development environments
    -not -path "*/venv/*"
    -not -path "*/.env/*"
    -not -path "*/vendor/*"
    -not -path "*/node_modules/*"
    
    # System updates
    -not -path "/var/lib/update-notifier/*"
    -not -path "/var/lib/unattended-upgrades/*"
    
    # Runtime files
    -not -path "/var/run/*"
    -not -path "*/run/*"
    -not -path "/run/*"
    
    # Socket files
    -not -path "*.sock"
    -not -path "*.socket"
    
    # Lock files
    -not -path "*.lock"
    -not -path "/var/lock/*"
    
    # Memory mapped files
    -not -path "/dev/shm/*"
    -not -path "/dev/mqueue/*"
    
    # System state
    -not -path "/var/lib/systemd/*"
    -not -path "/var/lib/NetworkManager/*"
    
    # Package specific
    -not -path "/var/lib/mysql/*"
    -not -path "/var/lib/postgresql/*"
    -not -path "/var/lib/redis/*"
    -not -path "/var/lib/mongodb/*"
    
    # Security specific
    -not -path "/var/lib/selinux/*"
    -not -path "/var/lib/apparmor/*"
    -not -path "/etc/ssl/private/*"
    -not -path "/etc/crypto-policies/*"
)

# Function to check if Desktop exists
check_desktop() {
    if [ ! -d "$DESKTOP_PATH" ]; then
        echo -e "${colors[RED]}Error:${colors[RESET]} Desktop directory does not exist!" >&2
        exit 1
    fi
}

# Function to validate directories
validate_directories() {
    local -a input_dirs=("$@")
    local -a valid_dirs=()
    
    for d in "${input_dirs[@]}"; do
        [[ -e "$d" ]] && valid_dirs+=("$(readlink -f -- "$d")") || true
    done
    
    if (( ${#valid_dirs[@]} == 0 )); then
        echo "No valid directories to scan." >&2
        exit 3
    fi
    
    echo "${valid_dirs[@]}"
}

# Function to scan for permissions
scan_permissions() {
    local file_name="$1"
    shift
    local -a dirs=("$@")
    
    # Arrays for results
    local -a list_0777 list_ww_f list_ww_d list_ww_d_nosticky list_suid list_sgid
    
    mapfile -t list_0777 < <(find "${dirs[@]}" "${FIND_COMMON[@]}" KATEX_INLINE_OPEN -type f -o -type d KATEX_INLINE_CLOSE -perm 0777 -printf "$FMT" 2>/dev/null || true)
    mapfile -t list_ww_f < <(find "${dirs[@]}" "${FIND_COMMON[@]}" -type f -perm -0002 -printf "$FMT" 2>/dev/null || true)
    mapfile -t list_ww_d < <(find "${dirs[@]}" "${FIND_COMMON[@]}" -type d -perm -0002 -printf "$FMT" 2>/dev/null || true)
    mapfile -t list_ww_d_nosticky < <(find "${dirs[@]}" "${FIND_COMMON[@]}" -type d -perm -0002 ! -perm -1000 -printf "$FMT" 2>/dev/null || true)
    mapfile -t list_suid < <(find "${dirs[@]}" "${FIND_COMMON[@]}" -type f -perm -4000 -printf "$FMT" 2>/dev/null || true)
    mapfile -t list_sgid < <(find "${dirs[@]}" "${FIND_COMMON[@]}" -type f -perm -2000 -printf "$FMT" 2>/dev/null || true)
    
    local total=$(( ${#list_0777[@]} + ${#list_ww_f[@]} + ${#list_ww_d[@]} + 
                   ${#list_ww_d_nosticky[@]} + ${#list_suid[@]} + ${#list_sgid[@]} ))

    # Generate report
    {
        echo "======================================================================="
        echo " Security Audit Report"
        echo " Host:     $HOST"
        echo " Date:     $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo " Run by:   $USER_RUN"
        echo " Scanned directories:"
        printf "  - %s\n" "${dirs[@]}"
        echo "======================================================================="
        
        print_section \
            "CRITICAL: Files/Directories with 777 permissions" \
            "HIGH" \
            "Anyone can read, write, and execute" \
            list_0777
            
        print_section \
            "World-writable files" \
            "HIGH" \
            "Files that can be modified by any user" \
            list_ww_f
            
        print_section \
            "World-writable directories" \
            "MEDIUM" \
            "Anyone can create files in these directories" \
            list_ww_d

        print_section \
            "World-writable directories without sticky bit" \
            "HIGH" \
            "Users can delete/replace files owned by others" \
            list_ww_d_nosticky

        print_section \
            "Files with SUID" \
            "HIGH" \
            "Programs run with owner permissions" \
            list_suid

        print_section \
            "Files/directories with SGID" \
            "HIGH/MEDIUM" \
            "Operates with group permissions" \
            list_sgid
        
        echo
        echo "Summary:"
        printf "  %-45s %6d\n" "Total issues found:" "$total"
        
        echo
        echo "Recommendations:"
        cat <<'RECO'
- Files:
    - default 0644 (rw-r--r--) or 0600 for sensitive files
    - executables 0755 (rwxr-xr-x) instead of 0777
    - avoid o+w (others write)
- Directories:
    - default 0755
    - shared directories: 1777 for public (e.g., /tmp), 2775 for group sharing
    - if o+w is needed, set sticky bit (chmod 1777)
- SUID/SGID:
    - minimize SUID/SGID files
    - keep packages updated
    - review and test before removing bits
RECO
        
    } | tee "$file_name"
    
    if (( total > 0 )); then
        echo -e "\n${colors[YELLOW]}Issues found. Report saved to: $file_name${colors[RESET]}"
        return 1
    else
        echo -e "\n${colors[GREEN]}No issues found. Report saved to: $file_name${colors[RESET]}"
        return 0
    fi
}

# Function to print section
print_section() {
    local title="$1"
    local severity="$2"
    local risk="$3"
    local -n arr="$4"

    echo
    echo "== $title =="
    echo "Risk level: $severity"
    echo "Why it's a problem: $risk"
    echo "Results (${#arr[@]}):"
    
    if (( ${#arr[@]} == 0 )); then
        echo "  - none"
        return
    fi
    
    printf "  %4s  %-10s  %-10s  %-10s  %10s  %-10s  %-5s  %s\n" \
        "oct" "sym" "user" "group" "size" "date" "time" "path"
    printf "  %s\n" "${arr[@]}"
}

# Function to generate report
generate_report() {
    local file_path="$1"
    shift
    local -a dirs=("$@")
    
    {
        echo "======================================================================="
        echo " Security Audit Report"
        echo " Host:     $HOST"
        echo " Date:     $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo " Run by:   $USER_RUN"
        echo " Scanned directories:"
        printf "  - %s\n" "${dirs[@]}"
        echo "======================================================================="
        
        print_section \
            "CRITICAL: Files/Directories with 777 permissions" \
            "HIGH" \
            "Anyone can read, write, and execute" \
            list_0777
        
        echo
        echo "Summary:"
        printf "  %-45s %6d\n" "Total issues found:" "$total"
        
        echo
        echo "Recommendations:"
        cat <<'RECO'
RECO
        
    } | tee "$file_path"
    
    if (( total > 0 )); then
        echo -e "\n${colors[YELLOW]}Issues found. Report saved to: $file_path${colors[RESET]}"
        return 1
    else
        echo -e "\n${colors[GREEN]}No issues found. Report saved to: $file_path${colors[RESET]}"
        return 0
    fi
}

# Main function
main() {
    check_desktop
    
    local file_name="$DESKTOP_PATH/$REPORT_FILE"
    touch "$file_name"
    
    echo -e "\n${colors[GREEN]}Choose scan type:${colors[RESET]}"
    echo -e "${colors[CYAN]}1${colors[RESET]} -> Automatic scan"
    echo -e "${colors[CYAN]}2${colors[RESET]} -> Custom path scan"
    
    read -t 120 -p "Enter 1 or 2: " option
    
    case "$option" in
        1)
            local dirs=($(validate_directories "${DEFAULT_DIRS[@]}"))
            scan_permissions "$file_name" "${dirs[@]}"
            ;;
        2)
            read -r -p "Enter correctly paths to scan (space-separated): " -a custom_dirs
            local dirs=($(validate_directories "${custom_dirs[@]}"))
            scan_permissions "$file_name" "${dirs[@]}"
            ;;
        *)
            echo -e "${colors[RED]}Invalid option. Please choose 1 or 2.${colors[RESET]}"
            exit 1
            ;;
    esac
}

# Start the script
main
