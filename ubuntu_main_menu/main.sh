#!/bin/bash
# Keep the script running
set -euo pipefail

# Global variables
PACKAGES=(
  boxes openssh-server vsftpd neofetch clamav snort fail2ban arp-scan 
)
LOGFILE="/var/log/script.log"

# Function to log messages to a log file and display them to the user
log_message() {
    local message="$1"
    printf "%s\n" "$message" | tee -a "$LOGFILE"
}

# Function to install packages if they are not already installed
install_package() {
    if ! dpkg -l | grep -qw "$1"; then
        log_message "Installing $1..."
        sudo apt-get install -y "$1"
    else
        log_message "$1 is already installed."
    fi
}

# Function to check if the script is run as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_message "This script must be run as root." >&2
        exit 1
    fi
}

# Main function
main() {
    log_message "Script started."

    # Check if script is run as root
    check_root

    # Install necessary packages
    for pkg in "${PACKAGES[@]}"; do
        install_package "$pkg"
    done

    while true; do
        # Display the Main Menu
        clear
        neofetch
        log_message 'Ｍａｉｎ Ｍｅｎｕ' | boxes -d stone -p a2v1

        # Present options to the user in three columns
        log_message "
1.  Update/Upgrade             2.  Install Applications      3.  Configure SSH
4.  Configure vsftpd           5.  UFW Setup                 6.  Security Enhancements
7.  Package Cleanup            8.  Service Management        9.  Log Management
10. Advanced Firewall Config   11. User Management           12. Backup System
13. System Info & Health Check 14. Network Configuration     15. Scheduled Tasks
16. System Performance         17. Install Unattended Upgrades 18. Network Traffic Analysis
19. Execute Custom Script      20. Set Up Intrusion Detection 21. Perform Malware Scanning
22. Run ARP Scan               23. Run Nmap Scan             24. Exit
"
        read -r option
        if ! [[ "$option" =~ ^[0-9]+$ ]]; then
            log_message "Invalid option. Please enter a number."
            continue
        fi

        handle_option "$option"
        log_message "Press Enter to continue..."
        read
    done
}


# Function to handle menu options
handle_option() {
    local option="$1"
    case "$option" in
        1)
            log_message "Updating and upgrading system..."
            sudo apt-get update -y && sudo apt-get upgrade -y
            install_package unattended-upgrades
            log_message "Update and Upgrade Complete"
            sleep 1
            ;;
        2)
            log_message "Installing applications..."
            local applications=(tilix neofetch snapd git gufw arp)
            for app in "${applications[@]}"; do
                install_package "$app"
            done
            log_message "Applications installed."
            ;;
        3)
            log_message "Editing SSH config..."
            install_package openssh-server
            sleep 0.5
            sudo nano /etc/ssh/sshd_config
            ;;
        4)
            install_package vsftpd
            log_message "Editing FTP config..."
            sleep 0.5
            sudo nano /etc/vsftpd.conf
            ;;
        5)
            log_message "Setting up UFW..."
            sudo ufw default allow outgoing
            sudo ufw default deny incoming
            sudo ufw allow http
            sudo ufw allow 80/tcp
            sudo ufw allow 21/udp
            sudo ufw limit 21/tcp
            sudo ufw limit ssh
            sudo ufw enable
            clear
            sudo systemctl status ufw.service
            log_message "UFW setup complete."
            sleep 2
            ;;
        6)
            log_message "Running Security Enhancements..."
            install_package lynis
            sudo lynis audit system
            ;;
        7)
            log_message "Performing Package Cleanup..."
            sudo apt-get autoclean
            sudo apt-get autoremove
            ;;
        8)
            log_message "Managing Services..."
            log_message "1. Kill a Service"
            log_message "2. View Services"
            read -r ser_man_opt
            if [ "$ser_man_opt" -eq 1 ]; then
                read -p "Enter Service name: " ser_name
                pkill "$ser_name"
            else
                systemctl --type=service --state=running
            fi
            ;;
        9)
            log_message "Managing Logs..."
            log_message "1. View a log file"
            log_message "2. Clear a log file"
            log_message "3. Send log file via mail"
            log_message "4. View Log Folder"
            read -r log_option
            case "$log_option" in
                1)
                    read -p "Enter the log file name to view: " log_file
                    sudo cat /var/log/"$log_file"
                    ;;
                2)
                    read -p "Enter the log file name to clear: " log_file
                    sudo truncate -s 0 /var/log/"$log_file"
                    ;;
                3)
                    read -p "Enter the log file name to send: " log_file
                    read -p "Enter the recipient email address: " email
                    sudo mail -s "Log File" "$email" < /var/log/"$log_file"
                    ;;
                4)
                    ls /var/log
                    ;;
                *)
                    log_message "Invalid option."
                    ;;
            esac
            ;;
        10)
            log_message "Advanced Firewall Configuration..."
            sleep 1.2
            log_message "1. Allow a port"
            log_message "2. Deny a port"
            log_message "3. Limit a port"
            read -r fw_option
            case "$fw_option" in
                1)
                    read -p "Enter the port number to allow: " port
                    sudo ufw allow "$port"
                    ;;
                2)
                    read -p "Enter the port number to deny: " port
                    sudo ufw deny "$port"
                    ;;
                3)
                    read -p "Enter the port number to limit: " port
                    sudo ufw limit "$port"
                    ;;
                *)
                    log_message "Invalid option."
                    ;;
            esac
            ;;
        11)
            log_message "Managing Users..."
            log_message "1. Add a user"
            log_message "2. Delete a user"
            log_message "3. View Users"
            log_message "4. Change User Password"
            read -r user_option
            case "$user_option" in
                1)
                    read -p "Enter the username to add: " username
                    sudo adduser "$username"
                    ;;
                2)
                    read -p "Enter the username to delete: " username
                    sudo deluser --remove-home "$username"
                    ;;
                3)
                    cat /etc/passwd
                    ;;
                4)
                    read -p "Enter the username to change password: " username
                    sudo passwd "$username"
                    ;;
                *)
                    log_message "Invalid option."
                    ;;
            esac
            ;;
        12)
            log_message "Backup and Restore Options..."
            log_message "1. Create a Backup"
            log_message "2. Mount Backup Storage"
            log_message "3. Restore from Backup"
            read -r backup_option
            case "$backup_option" in
                1)
                    log_message "Starting backup process..."
                    mkdir /mnt/backup
                    local BACKUP_DIR="/mnt/backup"
                    local DATE=$(date +%F_%T)
                    local BACKUP_NAME="backup_$DATE"
                    local EXCLUDE_LIST="--exclude=/proc --exclude=/sys --exclude=/tmp --exclude=/mnt --exclude=/dev --exclude=/run --exclude=/lost+found"
                    if [ ! -d "$BACKUP_DIR" ]; then
                        log_message "Backup directory $BACKUP_DIR does not exist. Please create it first."
                        exit 1
                    fi
                    rsync -aAXv / "$BACKUP_DIR/$BACKUP_NAME" $EXCLUDE_LIST
                    log_message "Backup completed successfully."
                    ;;
                2)
                    log_message "Mounting backup storage..."
                    local MOUNT_POINT="/mnt/backup"
                    local DEVICE="/dev/sdX1"
                    if [ ! -d "$MOUNT_POINT" ]; then
                        sudo mkdir -p "$MOUNT_POINT"
                    fi
                    sudo mount "$DEVICE" "$MOUNT_POINT"
                    if mountpoint -q "$MOUNT_POINT"; then
                        log_message "Backup storage mounted successfully at $MOUNT_POINT."
                    else
                        log_message "Failed to mount backup storage."
                    fi
                    ;;
                3)
                    log_message "Restoring from backup..."
                    local BACKUP_DIR="/mnt/backup"
                    local RESTORE_DEST="/"
                    log_message "Available backups:"
                    ls "$BACKUP_DIR"
                    read -p "Enter the name of the backup to restore: " BACKUP_NAME
                    if [ ! -d "$BACKUP_DIR/$BACKUP_NAME" ]; then
                        log_message "Backup $BACKUP_NAME does not exist."
                        exit 1
                    fi
                    rsync -aAXv "$BACKUP_DIR/$BACKUP_NAME/" "$RESTORE_DEST"
                    log_message "Restore completed successfully."
                    ;;
                *)
                    log_message "Invalid option."
                    ;;
            esac
            ;;
        13)
            log_message "System Information and Health Check..."
            log_message "System Uptime:"
            uptime
            log_message "Memory Usage:"
            free -h
            log_message "Disk Usage:"
            df -h
            log_message "CPU Information:"
            lscpu
            sleep 2
            install_package neofetch
            neofetch
            log_message "System Health Check Complete."
            ;;
        14)
            log_message "Viewing Network Configuration..."
            ifconfig
            sleep 3
            ;;
        15)
            log_message "Managing Scheduled Tasks..."
            log_message "1. List scheduled tasks"
            log_message "2. Add a scheduled task"
            log_message "3. Remove a scheduled task"
            read -r cron_option
            case "$cron_option" in
                1)
                    crontab -l
                    ;;
                2)
                    crontab -e
                    ;;
                3)
                    read -p "Enter the line number to remove: " line_num
                    crontab -l | sed "${line_num}d" | crontab -
                    ;;
                *)
                    log_message "Invalid option."
                    ;;
            esac
            ;;
        16)
            log_message "System Performance..."
            log_message "1. Install and run htop"
            log_message "2. Display CPU and memory usage"
            read -r performance_option
            case "$performance_option" in
                1)
                    install_package htop
                    htop
                    ;;
                2)
                    log_message "CPU and Memory Usage:"
                    top -bn1 | head -n 10
                    ;;
                *)
                    log_message "Invalid option."
                    ;;
            esac
            ;;
        17)
            log_message "Installing and configuring Unattended Upgrades..."
            install_package unattended-upgrades
            sudo dpkg-reconfigure --priority=low unattended-upgrades
            log_message "Unattended Upgrades configured."
            ;;
        18)
            log_message "Network Traffic Analysis..."
            install_package iftop
            sudo iftop -i "$(ip route | grep default | awk '{print $5}')"
            ;;
        19)
            log_message "Running custom script..."
            read -p "Enter the full path to the custom script: " script_path
            if [ -f "$script_path" ]; then
                chmod +x "$script_path"
                "$script_path"
            else
                log_message "File $script_path does not exist."
            fi
            ;;
        20)
            log_message "Setting up Intrusion Detection..."
            install_package snort
            sudo snort -A console -q -c /etc/snort/snort.conf -i "$(ip route | grep default | awk '{print $5}')"
            ;;
        21)
            log_message "Performing Malware Scanning..."
            sudo freshclam
            sudo clamscan -r /
            ;;
        22)
            log_message "Running ARP Scan..."
            sudo arp-scan -l
            ;;
        23)
            log_message "Running Nmap Scan..."
            read -p "Enter the target IP address or range: " target_ip
            sudo nmap -A "$target_ip"
            ;;
        24)
            log_message "Exiting..."
            exit 0
            ;;
        *)
            log_message "Invalid option. Please select a valid number between 1 and 23."
            ;;
    esac
}

# Execute the main function
main
