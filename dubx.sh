#!/bin/bash

# Color codes for pretty printing
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

# Check if Python is installed
function check_python() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}Python is not installed. Installing Python...${RESET}"
        pkg install python -y
    fi
}

# Check if numpy is installed
function check_numpy() {
    python3 -c "import numpy" &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}numpy is not installed. Installing numpy...${RESET}"
        pip3 install numpy
    fi
}

# Check if scapy is installed
function check_scapy() {
    python3 -c "import scapy" &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}scapy is not installed. Installing scapy...${RESET}"
        pip3 install scapy
    fi
}

# Display usage
function usage() {
    echo -e "${BLUE}Usage: amx.sh -f <capture.cap/.pcap>${RESET}"
    exit 1
}

# Progress bar function
function progress_bar() {
    local duration=$1
    local interval=0.1
    local count=$(echo "$duration / $interval" | bc)
    echo -n "["
    for ((i=0; i<$count; i++)); do
        echo -n "="
        sleep $interval
    done
    echo "]"
}

# Main script
if [ "$#" -ne 2 ]; then
    usage
fi

# Parse input arguments
while getopts "f:" opt; do
    case $opt in
        f)
            CAPTURE_FILE=$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done

# Check if the capture file exists
if [ ! -f "$CAPTURE_FILE" ]; then
    echo -e "${RED}File '$CAPTURE_FILE' does not exist.${RESET}"
    exit 1
fi

# Check and install dependencies
check_python
check_numpy
check_scapy

# Start the Python script with a progress bar
echo -e "${BLUE}Starting WPA/WPA2 key recovery on '$CAPTURE_FILE'...${RESET}"
progress_bar 10 &  # Simulating progress bar for 10 seconds, adjust as needed

# Run the Python script
python3 amx.py "$CAPTURE_FILE" | while IFS= read -r line; do
    if [[ "$line" == *"KEY FOUND!"* ]]; then
        echo -e "${GREEN}$line${RESET}"
    else
        echo "$line"
    fi
done
