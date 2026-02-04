#!/bin/bash

TEMPLATE_FILE="./template.txt"
INTERFACE="wlan0"

declare -A ALLOWED_IPS
declare -A WHITELIST

load_whitelist() {
    echo "[DNS-MONITOR] Loading whitelist from $TEMPLATE_FILE..."
    while read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | xargs | tr '[:upper:]' '[:lower:]')
        if [[ -n "$domain" ]]; then
            WHITELIST["$domain"]=1
            echo "[DNS-MONITOR] Added to whitelist: $domain"
        fi
    done < "$TEMPLATE_FILE"
    echo "[DNS-MONITOR] Whitelist loaded: ${!WHITELIST[@]}"
}

is_whitelisted() {
    local domain="$1"
    domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')
    for allowed in "${!WHITELIST[@]}"; do
        if [[ "$domain" == "$allowed" || "$domain" == *".$allowed" ]]; then
            echo "[DNS-MONITOR] Domain $domain matches whitelist entry: $allowed"
            return 0
        fi
    done
    echo "[DNS-MONITOR] Domain $domain NOT in whitelist"
    return 1
}

add_iptables_rule() {
    local ip="$1"
    if [[ -z "${ALLOWED_IPS[$ip]}" ]]; then
        ALLOWED_IPS["$ip"]=1
        sudo iptables -A FORWARD -i wlan0 -o eth0 -d "$ip" -j ACCEPT
        sudo iptables -A FORWARD -i eth0 -o wlan0 -s "$ip" -m state --state ESTABLISHED,RELATED -j ACCEPT
        echo "[IPTABLES] Allowed $ip"
    else
        echo "[IPTABLES] $ip already allowed, skipping"
    fi
}

dns_monitor() {
    load_whitelist
    echo "[DNS-MONITOR] Starting tshark on $INTERFACE..."
    echo "[DNS-MONITOR] Filter: dns.a"
    echo "[DNS-MONITOR] Waiting for DNS responses..."
    
    sudo stdbuf -oL tshark -i "$INTERFACE" -l -Y "dns.a" -T fields -e dns.qry.name -e dns.a 2>&1 | while read -r line; do
        echo "[DNS-MONITOR] Raw line: $line"
        
        if [[ "$line" == *"Capturing on"* ]] || [[ "$line" == *"Running as"* ]]; then
            echo "[DNS-MONITOR] tshark info: $line"
            continue
        fi
        
        domain=$(echo "$line" | awk '{print $1}')
        ips=$(echo "$line" | cut -f2-)
        
        echo "[DNS-MONITOR] Parsed domain: $domain"
        echo "[DNS-MONITOR] Parsed IPs: $ips"
        
        if [[ -n "$domain" ]]; then
            domain=$(echo "$domain" | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')
            for ip in $(echo "$ips" | tr ',' '\n' | tr '\t' '\n'); do
                [[ -z "$ip" ]] && continue
                echo "[DNS] $domain -> $ip"
                if is_whitelisted "$domain"; then
                    add_iptables_rule "$ip"
                fi
            done
        else
            echo "[DNS-MONITOR] No domain parsed from line"
        fi
    done
    
    echo "[DNS-MONITOR] tshark exited"
}

# --- CHECKS ---
sudo lsof -i :53
nmcli radio
rfkill list

# --- STOP SERVICES ---
sudo systemctl stop dnsmasq
sudo killall dnsmasq 2>/dev/null
sudo systemctl stop unbound

# --- SETUP INTERFACE ---
sudo nmcli radio wifi on
sudo ip link set wlan0 down
sudo ip addr flush dev wlan0
sudo ip link set wlan0 up
sudo ip addr add 10.10.0.1/24 dev wlan0

# --- IPTABLES FIREWALL SETUP ---
echo "[DEBUG] Flushing existing iptables rules..."
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

echo "[DEBUG] Default policy: DROP for all chains"

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# --- AP SUBNET (wlan0 - 10.10.0.0/24) ---
sudo iptables -A INPUT -i wlan0 -p udp --dport 67 -j ACCEPT
sudo iptables -A OUTPUT -o wlan0 -p udp --sport 67 -j ACCEPT
sudo iptables -A INPUT -i wlan0 -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -o wlan0 -p udp --sport 53 -j ACCEPT
sudo iptables -A INPUT -i wlan0 -p tcp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -o wlan0 -p tcp --sport 53 -j ACCEPT
sudo iptables -A INPUT -i wlan0 -p icmp -j ACCEPT
sudo iptables -A OUTPUT -o wlan0 -p icmp -j ACCEPT

# --- OUTBOUND FROM PI (eth0) ---
sudo iptables -A OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i eth0 -p udp --sport 53 -j ACCEPT
sudo iptables -A OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i eth0 -p tcp --sport 53 -j ACCEPT

# NAT for forwarded traffic
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

echo "[DEBUG] IPTABLES firewall setup complete."

# --- START SERVICES ---
sudo dnsmasq --conf-file=dnsmasq.conf

sudo hostapd hostapd-test.conf &
HOSTAPD_PID=$!
sleep 2

echo "[DEBUG] Starting DNS monitor..."
dns_monitor &
DNS_MONITOR_PID=$!
echo "[DEBUG] DNS monitor PID: $DNS_MONITOR_PID"

sleep 1
echo "[DEBUG] Starting pcap capture..."
sudo tshark -i wlan0 -w /tmp/hostap_session.pcap &
TSHARK_PID=$!

# --- CLEANUP ---
cleanup() {
    echo "Stopping services..."
    sudo kill $HOSTAPD_PID 2>/dev/null
    sudo kill $TSHARK_PID 2>/dev/null
    sudo kill $DNS_MONITOR_PID 2>/dev/null
    sudo pkill -f "tshark -i $INTERFACE -l -Y dns.a" 2>/dev/null
    wait $HOSTAPD_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    wait $DNS_MONITOR_PID 2>/dev/null
    sudo chmod 644 /tmp/hostap_session.pcap 2>/dev/null
    if [ -f /tmp/hostap_session.pcap ]; then
        cp /tmp/hostap_session.pcap ./hostap_session.pcap
        echo "hostap_session.pcap copied to current directory."
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

wait $HOSTAPD_PID $TSHARK_PID $DNS_MONITOR_PID